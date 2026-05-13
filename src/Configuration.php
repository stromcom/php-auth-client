<?php
declare(strict_types=1);

namespace Stromcom\AuthClient;

use Stromcom\AuthClient\Exception\ConfigurationException;

final class Configuration {

  public const string DEFAULT_ISSUER = 'https://auth.stromcom.cz';
  public const int DEFAULT_TIMEOUT = 10;
  public const int DEFAULT_JWKS_TTL = 3600;
  public const int DEFAULT_LEEWAY = 30;
  public const string DEFAULT_USER_AGENT = 'stromcom-auth-client-php/1.0';

  /** @var non-empty-string */
  public readonly string $issuer;
  public readonly string $clientId;
  public readonly ?string $clientSecret;
  public readonly ?string $redirectUri;
  /** @var list<string> */
  public readonly array $defaultScopes;
  public readonly int $timeout;
  public readonly int $jwksTtl;
  public readonly int $leeway;
  public readonly string $userAgent;

  public readonly string $authorizationEndpoint;
  public readonly string $tokenEndpoint;
  public readonly string $userInfoEndpoint;
  public readonly string $logoutEndpoint;
  public readonly string $jwksUri;

  /**
   * @param list<string> $defaultScopes
   */
  public function __construct(
    string $clientId,
    ?string $clientSecret = null,
    ?string $redirectUri = null,
    string $issuer = self::DEFAULT_ISSUER,
    array $defaultScopes = ['openid', 'profile', 'email', 'groups'],
    int $timeout = self::DEFAULT_TIMEOUT,
    int $jwksTtl = self::DEFAULT_JWKS_TTL,
    int $leeway = self::DEFAULT_LEEWAY,
    string $userAgent = self::DEFAULT_USER_AGENT,
    ?string $authorizationEndpoint = null,
    ?string $tokenEndpoint = null,
    ?string $userInfoEndpoint = null,
    ?string $logoutEndpoint = null,
    ?string $jwksUri = null,
  ) {
    if ($clientId === '') {
      throw new ConfigurationException('clientId cannot be empty.');
    }
    if ($timeout < 1) {
      throw new ConfigurationException('timeout must be a positive integer (seconds).');
    }
    if ($jwksTtl < 1) {
      throw new ConfigurationException('jwksTtl must be a positive integer (seconds).');
    }
    if ($leeway < 0) {
      throw new ConfigurationException('leeway must be zero or positive.');
    }
    if (!preg_match('#^https?://#', $issuer)) {
      throw new ConfigurationException('issuer must be an absolute http(s) URL.');
    }
    $normalizedIssuer = rtrim($issuer, '/');
    if ($normalizedIssuer === '') {
      throw new ConfigurationException('issuer must be an absolute http(s) URL.');
    }

    $this->clientId      = $clientId;
    $this->clientSecret  = $clientSecret;
    $this->redirectUri   = $redirectUri;
    $this->issuer        = $normalizedIssuer;
    $this->defaultScopes = $defaultScopes;
    $this->timeout       = $timeout;
    $this->jwksTtl       = $jwksTtl;
    $this->leeway        = $leeway;
    $this->userAgent     = $userAgent;

    $this->authorizationEndpoint = $authorizationEndpoint ?? ($this->issuer . '/oauth/authorize');
    $this->tokenEndpoint         = $tokenEndpoint         ?? ($this->issuer . '/oauth/token');
    $this->userInfoEndpoint      = $userInfoEndpoint      ?? ($this->issuer . '/me');
    $this->logoutEndpoint        = $logoutEndpoint        ?? ($this->issuer . '/oauth/logout');
    $this->jwksUri               = $jwksUri               ?? ($this->issuer . '/.well-known/jwks.json');
  }

  public function requireRedirectUri(): string {
    if ($this->redirectUri === null || $this->redirectUri === '') {
      throw new ConfigurationException('redirectUri is required for the authorization_code flow.');
    }
    return $this->redirectUri;
  }

  public function requireClientSecret(): string {
    if ($this->clientSecret === null || $this->clientSecret === '') {
      throw new ConfigurationException('clientSecret is required for confidential clients.');
    }
    return $this->clientSecret;
  }

}
