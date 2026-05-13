<?php
declare(strict_types=1);

namespace Stromcom\AuthClient;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token as JwtToken;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;
use Stromcom\AuthClient\Exception\TokenVerificationException;
use Stromcom\AuthClient\Exception\TransportException;
use Stromcom\AuthClient\Http\HttpClientInterface;
use Stromcom\AuthClient\Internal\JwkRsaKey;
use Stromcom\AuthClient\Internal\SystemClock;
use Stromcom\AuthClient\Jwks\JwksCacheInterface;
use Throwable;

final class TokenVerifier {

  public function __construct(
    private readonly Configuration $configuration,
    private readonly HttpClientInterface $httpClient,
    private readonly JwksCacheInterface $jwksCache,
  ) {}

  /**
   * Verifies the JWT signature, issuer, exp/nbf/iat (with leeway), optionally
   * audience, and the stromcom-specific `token_use` claim. Returns parsed
   * claims.
   *
   * JWT parsing and validation are delegated to lcobucci/jwt; the orchestration
   * (looking up the public key from JWKS by `kid`, transparent retry on key
   * rotation, RFC 9068 strict-mode token_use check) lives here.
   *
   * @param list<string>|null $expectedAudiences Acceptable `aud` values. Null skips audience check.
   *
   * @throws TokenVerificationException
   */
  public function verify(string $jwt, ?array $expectedAudiences = null): Claims {
    if ($jwt === '') {
      throw new TokenVerificationException('JWT is empty.');
    }
    $token = $this->parse($jwt);

    $alg = $token->headers()->get('alg');
    if ($alg !== 'RS256') {
      throw new TokenVerificationException(sprintf('Unsupported JWT alg "%s" (only RS256 is supported).', is_string($alg) ? $alg : '(missing)'));
    }

    $kid = $token->headers()->get('kid');
    $jwk = $this->findJwk(is_string($kid) ? $kid : null);
    if ($jwk === null) {
      $this->jwksCache->delete($this->configuration->jwksUri);
      $jwk = $this->findJwk(is_string($kid) ? $kid : null, forceRefresh: true);
    }
    if ($jwk === null) {
      throw new TokenVerificationException(sprintf('No matching JWK found for kid "%s".', is_string($kid) ? $kid : '(none)'));
    }

    $signer = new Sha256();
    $verificationKey = InMemory::plainText(JwkRsaKey::toPem($jwk));

    $constraints = [
      new SignedWith($signer, $verificationKey),
      new IssuedBy($this->configuration->issuer),
      new LooseValidAt(
        new SystemClock(),
        new DateInterval('PT' . $this->configuration->leeway . 'S'),
      ),
    ];
    if ($expectedAudiences !== null) {
      foreach ($expectedAudiences as $aud) {
        if ($aud === '') {
          continue;
        }
        $constraints[] = new PermittedFor($aud);
      }
    }

    try {
      (new Validator())->assert($token, ...$constraints);
    } catch (RequiredConstraintsViolated $e) {
      throw new TokenVerificationException('JWT validation failed: ' . $e->getMessage(), previous: $e);
    }

    $payload = self::extractClaims($token);

    if (!isset($payload['token_use']) || !is_string($payload['token_use']) || $payload['token_use'] === '') {
      throw new TokenVerificationException('JWT is missing token_use claim.');
    }

    return Claims::fromPayload($payload);
  }

  /**
   * @return array<string, mixed>
   */
  public function loadJwks(bool $forceRefresh = false): array {
    if (!$forceRefresh) {
      $cached = $this->jwksCache->get($this->configuration->jwksUri);
      if ($cached !== null) {
        return $cached;
      }
    }

    try {
      $response = $this->httpClient->request('GET', $this->configuration->jwksUri, [
        'Accept'     => 'application/json',
        'User-Agent' => $this->configuration->userAgent,
      ]);
    } catch (TransportException $e) {
      throw new TokenVerificationException('Could not fetch JWKS: ' . $e->getMessage(), previous: $e);
    }

    if ($response->statusCode !== 200) {
      throw new TokenVerificationException(sprintf('JWKS endpoint returned HTTP %d.', $response->statusCode));
    }

    $decoded = json_decode($response->body, true);
    if (!is_array($decoded) || !isset($decoded['keys']) || !is_array($decoded['keys'])) {
      throw new TokenVerificationException('JWKS endpoint returned malformed JSON.');
    }

    /** @var array<string, mixed> $decoded */
    $this->jwksCache->set($this->configuration->jwksUri, $decoded, $this->configuration->jwksTtl);

    return $decoded;
  }

  /**
   * @param non-empty-string $jwt
   */
  private function parse(string $jwt): UnencryptedToken {
    $parser = new Parser(new JoseEncoder());
    try {
      $token = $parser->parse($jwt);
    } catch (Throwable $e) {
      throw new TokenVerificationException('Malformed JWT: ' . $e->getMessage(), previous: $e);
    }
    if (!$token instanceof UnencryptedToken) {
      throw new TokenVerificationException('Encrypted JWTs are not supported.');
    }
    return $token;
  }

  /**
   * @return array<string, mixed>|null
   */
  private function findJwk(?string $kid, bool $forceRefresh = false): ?array {
    $jwks = $this->loadJwks($forceRefresh);
    if (!isset($jwks['keys']) || !is_array($jwks['keys'])) {
      return null;
    }
    foreach ($jwks['keys'] as $key) {
      if (!is_array($key)) {
        continue;
      }
      if ($kid !== null) {
        if (isset($key['kid']) && $key['kid'] === $kid) {
          /** @var array<string, mixed> $key */
          return $key;
        }
        continue;
      }
      /** @var array<string, mixed> $key */
      return $key;
    }
    return null;
  }

  /**
   * lcobucci's `claims()->all()` converts iat/nbf/exp to DateTimeImmutable;
   * Claims::fromPayload expects ints. Convert back at the boundary.
   *
   * @return array<string, mixed>
   */
  private static function extractClaims(JwtToken $token): array {
    if (!$token instanceof UnencryptedToken) {
      return [];
    }
    $out = [];
    foreach ($token->claims()->all() as $name => $value) {
      $out[$name] = $value instanceof DateTimeImmutable ? $value->getTimestamp() : $value;
    }
    return $out;
  }

}
