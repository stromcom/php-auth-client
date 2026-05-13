<?php
declare(strict_types=1);

namespace Stromcom\AuthClient;

use Stromcom\AuthClient\Exception\AuthClientException;
use Stromcom\AuthClient\Exception\OAuthServerException;
use Stromcom\AuthClient\Exception\TransportException;
use Stromcom\AuthClient\Http\CurlHttpClient;
use Stromcom\AuthClient\Http\HttpClientInterface;
use Stromcom\AuthClient\Http\RawResponse;
use Stromcom\AuthClient\Jwks\InMemoryJwksCache;
use Stromcom\AuthClient\Jwks\JwksCacheInterface;

/**
 * Main entry point for the auth.stromcom.cz client.
 *
 * @example
 *   $auth = new Client(new Configuration(
 *       clientId:     'cli_xxxxxxxxxxxxxxxx',
 *       clientSecret: '...',
 *       redirectUri:  'https://app.example.com/oauth/callback',
 *   ));
 *
 *   // 1. Web app login: redirect user
 *   [$url, $pkce, $state] = $auth->beginAuthorization();
 *   header('Location: ' . $url);
 *
 *   // 2. Callback: exchange code → tokens
 *   $tokens = $auth->exchangeCode($_GET['code'], $pkce->verifier);
 *
 *   // 3. Verify access token in your API
 *   $claims = $auth->verify($tokens->accessToken);
 */
final class Client {

  public readonly Configuration $configuration;
  private readonly HttpClientInterface $httpClient;
  private readonly JwksCacheInterface $jwksCache;
  private ?TokenVerifier $verifier = null;

  public function __construct(
    Configuration $configuration,
    ?HttpClientInterface $httpClient = null,
    ?JwksCacheInterface $jwksCache = null,
  ) {
    $this->configuration = $configuration;
    $this->httpClient = $httpClient ?? new CurlHttpClient($configuration->timeout);
    $this->jwksCache = $jwksCache ?? new InMemoryJwksCache();
  }

  /**
   * Build the authorization URL for the authorization_code + PKCE flow.
   *
   * Returns the URL, the PKCE pair (keep `verifier` in session, you'll need it
   * for `exchangeCode`) and the `state` value (compare against the value the
   * server will echo back in the callback to defeat CSRF).
   *
   * @param list<string>|null $scopes Overrides Configuration::$defaultScopes.
   * @param array<string, string> $extraParams Additional query parameters (e.g. `prompt=login`).
   *
   * @return array{0: string, 1: Pkce, 2: string}
   */
  public function beginAuthorization(?array $scopes = null, array $extraParams = []): array {
    $pkce = Pkce::generate();
    $state = bin2hex(random_bytes(16));

    $params = array_merge([
      'response_type'         => 'code',
      'client_id'             => $this->configuration->clientId,
      'redirect_uri'          => $this->configuration->requireRedirectUri(),
      'scope'                 => implode(' ', $scopes ?? $this->configuration->defaultScopes),
      'state'                 => $state,
      'code_challenge'        => $pkce->challenge,
      'code_challenge_method' => $pkce->method,
    ], $extraParams);

    return [
      $this->configuration->authorizationEndpoint . '?' . http_build_query($params),
      $pkce,
      $state,
    ];
  }

  /**
   * Exchange an authorization code for tokens.
   */
  public function exchangeCode(string $code, string $codeVerifier): TokenSet {
    $params = [
      'grant_type'    => 'authorization_code',
      'client_id'     => $this->configuration->clientId,
      'redirect_uri'  => $this->configuration->requireRedirectUri(),
      'code'          => $code,
      'code_verifier' => $codeVerifier,
    ];
    if ($this->configuration->clientSecret !== null && $this->configuration->clientSecret !== '') {
      $params['client_secret'] = $this->configuration->clientSecret;
    }

    return TokenSet::fromResponse($this->postToken($params), time());
  }

  /**
   * Refresh an access token using a refresh token. The auth server rotates
   * refresh tokens — store the new `refreshToken` from the result immediately
   * and discard the old one.
   */
  public function refresh(string $refreshToken): TokenSet {
    $params = [
      'grant_type'    => 'refresh_token',
      'client_id'     => $this->configuration->clientId,
      'refresh_token' => $refreshToken,
    ];
    if ($this->configuration->clientSecret !== null && $this->configuration->clientSecret !== '') {
      $params['client_secret'] = $this->configuration->clientSecret;
    }

    return TokenSet::fromResponse($this->postToken($params), time());
  }

  /**
   * Machine-to-machine flow. Returns a service access token (no refresh token).
   *
   * @param list<string>|null $scopes
   */
  public function clientCredentials(?array $scopes = null): TokenSet {
    $params = [
      'grant_type'    => 'client_credentials',
      'client_id'     => $this->configuration->clientId,
      'client_secret' => $this->configuration->requireClientSecret(),
    ];
    if ($scopes !== null && $scopes !== []) {
      $params['scope'] = implode(' ', $scopes);
    }

    return TokenSet::fromResponse($this->postToken($params), time());
  }

  /**
   * Fetch UserInfo for the bearer token (`GET /me`). Slower than `verify()`
   * because it hits the auth server every call — prefer JWT verification for
   * per-request authorization.
   *
   * @return array<string, mixed>
   */
  public function userInfo(string $accessToken): array {
    try {
      $response = $this->httpClient->request('GET', $this->configuration->userInfoEndpoint, [
        'Authorization' => 'Bearer ' . $accessToken,
        'Accept'        => 'application/json',
        'User-Agent'    => $this->configuration->userAgent,
      ]);
    } catch (TransportException $e) {
      throw new AuthClientException('Could not call userinfo endpoint: ' . $e->getMessage(), previous: $e);
    }

    return $this->decodeJsonOrThrow($response);
  }

  /**
   * Verify a JWT access token against the JWKS published by the auth server.
   *
   * @param list<string>|null $expectedAudiences When set, the token's `aud`
   *   claim must contain at least one of these values. Defaults to the
   *   client's own `client_id`.
   */
  public function verify(string $jwt, ?array $expectedAudiences = null): Claims {
    return $this->verifier()->verify(
      $jwt,
      $expectedAudiences ?? [$this->configuration->clientId],
    );
  }

  public function verifier(): TokenVerifier {
    return $this->verifier ??= new TokenVerifier($this->configuration, $this->httpClient, $this->jwksCache);
  }

  /**
   * Build the logout URL. Cookies on auth.stromcom.cz are cleared; tokens
   * already issued remain valid until they expire.
   */
  public function logoutUrl(?string $postLogoutRedirectUri = null): string {
    $params = [];
    if ($postLogoutRedirectUri !== null && $postLogoutRedirectUri !== '') {
      $params['post_logout_redirect_uri'] = $postLogoutRedirectUri;
    }
    $query = $params === [] ? '' : '?' . http_build_query($params);
    return $this->configuration->logoutEndpoint . $query;
  }

  /**
   * Fetch the OIDC discovery document.
   *
   * @return array<string, mixed>
   */
  public function discover(): array {
    try {
      $response = $this->httpClient->request('GET', $this->configuration->issuer . '/.well-known/openid-configuration', [
        'Accept'     => 'application/json',
        'User-Agent' => $this->configuration->userAgent,
      ]);
    } catch (TransportException $e) {
      throw new AuthClientException('Could not call discovery endpoint: ' . $e->getMessage(), previous: $e);
    }

    return $this->decodeJsonOrThrow($response);
  }

  /**
   * @param array<string, string> $params
   *
   * @return array<string, mixed>
   */
  private function postToken(array $params): array {
    try {
      $response = $this->httpClient->request(
        'POST',
        $this->configuration->tokenEndpoint,
        [
          'Content-Type' => 'application/x-www-form-urlencoded',
          'Accept'       => 'application/json',
          'User-Agent'   => $this->configuration->userAgent,
        ],
        http_build_query($params),
      );
    } catch (TransportException $e) {
      throw new AuthClientException('Could not call token endpoint: ' . $e->getMessage(), previous: $e);
    }

    return $this->decodeJsonOrThrow($response);
  }

  /**
   * @return array<string, mixed>
   */
  private function decodeJsonOrThrow(RawResponse $response): array {
    $decoded = $response->body === '' ? null : json_decode($response->body, true);

    if ($response->statusCode >= 200 && $response->statusCode < 300) {
      if (!is_array($decoded)) {
        throw new AuthClientException(sprintf(
          'Unexpected non-JSON response (status %d): %s',
          $response->statusCode,
          substr($response->body, 0, 200),
        ));
      }
      /** @var array<string, mixed> $decoded */
      return $decoded;
    }

    if (is_array($decoded) && isset($decoded['error']) && is_string($decoded['error'])) {
      throw new OAuthServerException(
        statusCode:       $response->statusCode,
        errorCode:        $decoded['error'],
        errorDescription: isset($decoded['error_description']) && is_string($decoded['error_description']) ? $decoded['error_description'] : null,
        errorUri:         isset($decoded['error_uri']) && is_string($decoded['error_uri']) ? $decoded['error_uri'] : null,
        raw:              $decoded,
      );
    }

    if (is_array($decoded) && isset($decoded['error']) && is_array($decoded['error'])) {
      $err = $decoded['error'];
      $code = isset($err['code']) && is_string($err['code']) ? $err['code'] : 'unknown_error';
      $message = isset($err['message']) && is_string($err['message']) ? $err['message'] : null;
      throw new OAuthServerException(
        statusCode:       $response->statusCode,
        errorCode:        $code,
        errorDescription: $message,
        errorUri:         null,
        raw:              $decoded,
      );
    }

    throw new AuthClientException(sprintf(
      'HTTP %d from %s: %s',
      $response->statusCode,
      $this->configuration->issuer,
      substr($response->body, 0, 200),
    ));
  }

}
