<?php
declare(strict_types=1);

namespace Stromcom\AuthClient;

use Stromcom\AuthClient\Exception\AuthorizationException;

final class Claims {

  /**
   * @param list<string> $audiences
   * @param list<string> $scopes
   * @param list<string> $roles
   * @param list<string> $groups
   * @param array<string, mixed> $all
   */
  public function __construct(
    public readonly string $subject,
    public readonly string $issuer,
    public readonly array $audiences,
    public readonly int $issuedAt,
    public readonly int $expiresAt,
    public readonly ?string $jti,
    public readonly string $tokenUse,
    public readonly ?string $email,
    public readonly ?bool $emailVerified,
    public readonly ?string $name,
    public readonly ?string $givenName,
    public readonly ?string $familyName,
    public readonly ?string $phoneNumber,
    public readonly ?bool $phoneNumberVerified,
    public readonly array $scopes,
    public readonly array $roles,
    public readonly array $groups,
    public readonly bool $isAdmin,
    public readonly ?string $clientId,
    public readonly ?string $clientName,
    public readonly array $all,
  ) {}

  /**
   * @param array<string, mixed> $payload
   */
  public static function fromPayload(array $payload): self {
    return new self(
      subject:             self::stringClaim($payload, 'sub') ?? '',
      issuer:              self::stringClaim($payload, 'iss') ?? '',
      audiences:           self::audiences($payload),
      issuedAt:            self::intClaim($payload, 'iat') ?? 0,
      expiresAt:           self::intClaim($payload, 'exp') ?? 0,
      jti:                 self::stringClaim($payload, 'jti'),
      tokenUse:            self::stringClaim($payload, 'token_use') ?? '',
      email:               self::stringClaim($payload, 'email'),
      emailVerified:       isset($payload['email_verified']) && is_bool($payload['email_verified']) ? $payload['email_verified'] : null,
      name:                self::stringClaim($payload, 'name'),
      givenName:           self::stringClaim($payload, 'given_name'),
      familyName:          self::stringClaim($payload, 'family_name'),
      phoneNumber:         self::stringClaim($payload, 'phone_number'),
      phoneNumberVerified: isset($payload['phone_number_verified']) && is_bool($payload['phone_number_verified']) ? $payload['phone_number_verified'] : null,
      scopes:              self::stringList($payload, 'scopes'),
      roles:               self::stringList($payload, 'roles'),
      groups:              self::stringList($payload, 'groups'),
      isAdmin:             isset($payload['is_admin']) && $payload['is_admin'] === true,
      clientId:            self::stringClaim($payload, 'client_id'),
      clientName:          self::stringClaim($payload, 'client_name'),
      all:                 $payload,
    );
  }

  public function isService(): bool {
    return $this->tokenUse === 'service';
  }

  public function isUser(): bool {
    return $this->tokenUse === 'user';
  }

  public function hasRole(string $role): bool {
    return in_array($role, $this->roles, true);
  }

  public function hasGroup(string $group): bool {
    return in_array($group, $this->groups, true);
  }

  public function hasScope(string $scope): bool {
    return in_array($scope, $this->scopes, true);
  }

  public function hasAnyRole(string ...$roles): bool {
    foreach ($roles as $role) {
      if ($this->hasRole($role)) {
        return true;
      }
    }
    return false;
  }

  public function hasAllRoles(string ...$roles): bool {
    foreach ($roles as $role) {
      if (!$this->hasRole($role)) {
        return false;
      }
    }
    return $roles !== [];
  }

  public function hasAnyGroup(string ...$groups): bool {
    foreach ($groups as $group) {
      if ($this->hasGroup($group)) {
        return true;
      }
    }
    return false;
  }

  public function hasAllGroups(string ...$groups): bool {
    foreach ($groups as $group) {
      if (!$this->hasGroup($group)) {
        return false;
      }
    }
    return $groups !== [];
  }

  /**
   * Returns only the roles that belong to the given project prefix, e.g. for
   * `prefix="translator"` the role `translator.editor` becomes `editor`.
   *
   * @return list<string>
   */
  public function rolesForProject(string $projectPrefix): array {
    $prefix = $projectPrefix . '.';
    $out = [];
    foreach ($this->roles as $role) {
      if (str_starts_with($role, $prefix)) {
        $out[] = substr($role, strlen($prefix));
      }
    }
    return $out;
  }

  public function hasProjectRole(string $projectPrefix, string $role): bool {
    return $this->hasRole($projectPrefix . '.' . $role);
  }

  /**
   * @throws AuthorizationException
   */
  public function requireRole(string $role): void {
    if (!$this->hasRole($role)) {
      throw AuthorizationException::missingRole($role);
    }
  }

  /**
   * @throws AuthorizationException
   */
  public function requireAnyRole(string ...$roles): void {
    if (!$this->hasAnyRole(...$roles)) {
      throw AuthorizationException::missingRole(implode(' | ', $roles));
    }
  }

  /**
   * @throws AuthorizationException
   */
  public function requireGroup(string $group): void {
    if (!$this->hasGroup($group)) {
      throw AuthorizationException::missingGroup($group);
    }
  }

  /**
   * @throws AuthorizationException
   */
  public function requireScope(string $scope): void {
    if (!$this->hasScope($scope)) {
      throw AuthorizationException::missingScope($scope);
    }
  }

  /**
   * @throws AuthorizationException
   */
  public function requireUserToken(): void {
    if (!$this->isUser()) {
      throw AuthorizationException::wrongTokenUse('user', $this->tokenUse);
    }
  }

  /**
   * @throws AuthorizationException
   */
  public function requireServiceToken(): void {
    if (!$this->isService()) {
      throw AuthorizationException::wrongTokenUse('service', $this->tokenUse);
    }
  }

  public function audience(): ?string {
    return $this->audiences[0] ?? null;
  }

  public function isExpired(?int $now = null): bool {
    return ($now ?? time()) >= $this->expiresAt;
  }

  public function secondsUntilExpiration(?int $now = null): int {
    return max(0, $this->expiresAt - ($now ?? time()));
  }

  /**
   * Best-effort human label: name → email → client_name → subject.
   */
  public function displayName(): string {
    if ($this->name !== null && $this->name !== '') {
      return $this->name;
    }
    if ($this->email !== null && $this->email !== '') {
      return $this->email;
    }
    if ($this->clientName !== null && $this->clientName !== '') {
      return $this->clientName;
    }
    return $this->subject;
  }

  /**
   * Grab an arbitrary raw claim (escape hatch for non-standard claims).
   */
  public function claim(string $name): mixed {
    return $this->all[$name] ?? null;
  }

  /**
   * @param array<string, mixed> $payload
   */
  private static function stringClaim(array $payload, string $key): ?string {
    if (!isset($payload[$key])) {
      return null;
    }
    $value = $payload[$key];
    return is_string($value) ? $value : null;
  }

  /**
   * @param array<string, mixed> $payload
   */
  private static function intClaim(array $payload, string $key): ?int {
    if (!isset($payload[$key])) {
      return null;
    }
    $value = $payload[$key];
    if (is_int($value)) {
      return $value;
    }
    if (is_float($value)) {
      return (int) $value;
    }
    return null;
  }

  /**
   * @param array<string, mixed> $payload
   * @return list<string>
   */
  private static function audiences(array $payload): array {
    if (!isset($payload['aud'])) {
      return [];
    }
    $aud = $payload['aud'];
    if (is_string($aud)) {
      return [$aud];
    }
    if (is_array($aud)) {
      $out = [];
      foreach ($aud as $item) {
        if (is_string($item)) {
          $out[] = $item;
        }
      }
      return $out;
    }
    return [];
  }

  /**
   * @param array<string, mixed> $payload
   * @return list<string>
   */
  private static function stringList(array $payload, string $key): array {
    if (!isset($payload[$key])) {
      return [];
    }
    $value = $payload[$key];
    if (is_string($value)) {
      $value = preg_split('/\s+/', trim($value)) ?: [];
      return array_values(array_filter($value, static fn($v): bool => $v !== ''));
    }
    if (is_array($value)) {
      $out = [];
      foreach ($value as $item) {
        if (is_string($item)) {
          $out[] = $item;
        }
      }
      return $out;
    }
    return [];
  }

}
