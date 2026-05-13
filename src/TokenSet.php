<?php
declare(strict_types=1);

namespace Stromcom\AuthClient;

final class TokenSet {

  /**
   * @param array<string, mixed> $raw The raw decoded token response.
   */
  public function __construct(
    public readonly string $accessToken,
    public readonly string $tokenType,
    public readonly int $expiresIn,
    public readonly int $expiresAt,
    public readonly ?string $refreshToken,
    public readonly ?string $idToken,
    public readonly ?string $scope,
    public readonly array $raw,
  ) {}

  /**
   * @param array<string, mixed> $response The decoded body of `POST /oauth/token`.
   */
  public static function fromResponse(array $response, int $now): self {
    $accessToken = isset($response['access_token']) && is_string($response['access_token']) ? $response['access_token'] : '';
    $tokenType = isset($response['token_type']) && is_string($response['token_type']) ? $response['token_type'] : 'Bearer';
    $expiresIn = isset($response['expires_in']) && is_int($response['expires_in']) ? $response['expires_in'] : 0;
    $refreshToken = isset($response['refresh_token']) && is_string($response['refresh_token']) ? $response['refresh_token'] : null;
    $idToken = isset($response['id_token']) && is_string($response['id_token']) ? $response['id_token'] : null;
    $scope = isset($response['scope']) && is_string($response['scope']) ? $response['scope'] : null;

    return new self(
      accessToken: $accessToken,
      tokenType:   $tokenType,
      expiresIn:   $expiresIn,
      expiresAt:   $now + $expiresIn,
      refreshToken: $refreshToken,
      idToken:     $idToken,
      scope:       $scope,
      raw:         $response,
    );
  }

  public function isExpired(int $now, int $leewaySeconds = 30): bool {
    return $now + $leewaySeconds >= $this->expiresAt;
  }

  public function authorizationHeader(): string {
    return $this->tokenType . ' ' . $this->accessToken;
  }

}
