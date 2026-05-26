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
   * Verify an RFC 9068 access token (JWT Profile for OAuth 2.0 Access Tokens).
   *
   * Enforces, per RFC 9068 §2.1–2.2:
   *  - JOSE header `typ` MUST be `at+jwt` (or `application/at+jwt`).
   *  - `alg` MUST be RS256.
   *  - REQUIRED claims present: `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti`.
   *  - Signature verifies against JWKS by `kid`.
   *  - `iss` equals Configuration::$issuer.
   *  - `exp`/`nbf`/`iat` valid w.r.t. clock (with leeway).
   *  - `aud` contains `$expectedAudience` (the resource server identifier — for
   *    this client that is typically Configuration::$clientId, but resource APIs
   *    pass their own audience).
   *
   * Note: `token_use` is a stromcom-specific extension claim, NOT defined by
   * RFC 9068. It is preserved on `Claims::$tokenUse` when present but is not
   * required by this verifier.
   *
   * @throws TokenVerificationException
   */
  public function verify(string $jwt, string $expectedAudience): Claims {
    [$token, $payload] = $this->verifyCore($jwt, $expectedAudience);

    $rawTyp = $token->headers()->get('typ');
    $typ = $this->normalizeTyp(is_string($rawTyp) ? $rawTyp : null);
    if ($typ === null) {
      throw new TokenVerificationException(
        'JWT is missing JOSE "typ" header — RFC 9068 access tokens MUST set typ=at+jwt.',
      );
    }
    if ($typ !== 'at+jwt') {
      throw new TokenVerificationException(sprintf(
        'Unexpected JWT typ "%s" — RFC 9068 access tokens MUST set typ=at+jwt. '
        . 'For OIDC id_tokens use verifyIdToken() instead.',
        $typ,
      ));
    }

    self::requireStringClaim($payload, 'sub');
    self::requireStringClaim($payload, 'client_id');
    self::requireStringClaim($payload, 'jti');
    self::requireIntClaim($payload, 'iat');

    return Claims::fromPayload($payload);
  }

  /**
   * Verify an OIDC Core 1.0 id_token per §3.1.3.7.
   *
   * Enforces:
   *  - `alg` MUST be RS256.
   *  - JOSE `typ` MUST NOT be `at+jwt` (prevents access-token / id-token
   *    confusion per RFC 8725 §3.11).
   *  - Signature verifies against JWKS.
   *  - `iss` equals Configuration::$issuer.
   *  - `aud` contains Configuration::$clientId.
   *  - When `aud` is multi-valued OR `azp` is present, `azp` MUST equal
   *    Configuration::$clientId.
   *  - `exp`/`iat` valid w.r.t. clock (with leeway).
   *  - `nonce` MUST be present and equal to `$expectedNonce` (timing-safe).
   *  - REQUIRED claims present: `iss`, `sub`, `aud`, `exp`, `iat`.
   *
   * Pass the nonce you persisted from `Client::beginAuthorization()`; after a
   * successful call invalidate it in your session (one-time use).
   *
   * @throws TokenVerificationException
   */
  public function verifyIdToken(string $jwt, string $expectedNonce): Claims {
    if ($expectedNonce === '') {
      throw new TokenVerificationException('Expected nonce must be a non-empty string.');
    }

    [$token, $payload] = $this->verifyCore($jwt, $this->configuration->clientId);

    $rawTyp = $token->headers()->get('typ');
    $typ = $this->normalizeTyp(is_string($rawTyp) ? $rawTyp : null);
    if ($typ === 'at+jwt') {
      throw new TokenVerificationException(
        'Refusing to verify a token with typ=at+jwt as an OIDC id_token (token confusion).',
      );
    }

    self::requireStringClaim($payload, 'sub');
    self::requireIntClaim($payload, 'iat');

    $aud = $payload['aud'] ?? null;
    $audIsMulti = is_array($aud) && count($aud) > 1;
    $azp = $payload['azp'] ?? null;
    if ($audIsMulti || $azp !== null) {
      if (!is_string($azp) || $azp === '') {
        throw new TokenVerificationException(
          'OIDC id_token with multiple audiences or `azp` requires a non-empty `azp` claim.',
        );
      }
      if (!hash_equals($this->configuration->clientId, $azp)) {
        throw new TokenVerificationException(sprintf(
          'OIDC id_token `azp` "%s" does not match this client_id.',
          $azp,
        ));
      }
    }

    $nonce = $payload['nonce'] ?? null;
    if (!is_string($nonce) || $nonce === '') {
      throw new TokenVerificationException('OIDC id_token is missing the `nonce` claim.');
    }
    if (!hash_equals($expectedNonce, $nonce)) {
      throw new TokenVerificationException('OIDC id_token `nonce` does not match the expected value.');
    }

    return Claims::fromPayload($payload);
  }

  /**
   * Shared core: parse, alg check, JWKS lookup (with kid-rotation retry),
   * signature verification, iss / exp / nbf / iat (with leeway), aud.
   *
   * @return array{0: UnencryptedToken, 1: array<string, mixed>}
   *
   * @throws TokenVerificationException
   */
  private function verifyCore(string $jwt, string $expectedAudience): array {
    if ($jwt === '') {
      throw new TokenVerificationException('JWT is empty.');
    }
    if ($expectedAudience === '') {
      throw new TokenVerificationException('Expected audience must be a non-empty string.');
    }

    $token = $this->parse($jwt);

    $alg = $token->headers()->get('alg');
    if ($alg !== 'RS256') {
      throw new TokenVerificationException(sprintf(
        'Unsupported JWT alg "%s" (only RS256 is supported).',
        is_string($alg) ? $alg : '(missing)',
      ));
    }

    $kid = $token->headers()->get('kid');
    $jwk = $this->findJwk(is_string($kid) ? $kid : null);
    if ($jwk === null) {
      $this->jwksCache->delete($this->configuration->jwksUri);
      $jwk = $this->findJwk(is_string($kid) ? $kid : null, forceRefresh: true);
    }
    if ($jwk === null) {
      throw new TokenVerificationException(sprintf(
        'No matching JWK found for kid "%s".',
        is_string($kid) ? $kid : '(none)',
      ));
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
      new PermittedFor($expectedAudience),
    ];

    try {
      (new Validator())->assert($token, ...$constraints);
    } catch (RequiredConstraintsViolated $e) {
      throw new TokenVerificationException('JWT validation failed: ' . $e->getMessage(), previous: $e);
    }

    return [$token, self::extractClaims($token)];
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
   * Per RFC 7515 §4.1.9, producers SHOULD omit the "application/" prefix.
   * Accept both forms; normalize to lowercase, prefix-stripped.
   */
  private function normalizeTyp(?string $typ): ?string {
    if ($typ === null) {
      return null;
    }
    $lower = strtolower($typ);
    if (str_starts_with($lower, 'application/')) {
      $lower = substr($lower, strlen('application/'));
    }
    return $lower === '' ? null : $lower;
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
   * @param array<string, mixed> $payload
   */
  private static function requireStringClaim(array $payload, string $name): void {
    $value = $payload[$name] ?? null;
    if (!is_string($value) || $value === '') {
      throw new TokenVerificationException(sprintf('JWT is missing required string claim "%s".', $name));
    }
  }

  /**
   * @param array<string, mixed> $payload
   */
  private static function requireIntClaim(array $payload, string $name): void {
    $value = $payload[$name] ?? null;
    if (!is_int($value)) {
      throw new TokenVerificationException(sprintf('JWT is missing required integer claim "%s".', $name));
    }
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
