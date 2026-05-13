<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Exception;

final class AuthorizationException extends AuthClientException {

  public static function missingRole(string $role): self {
    return new self(sprintf('Missing required role "%s".', $role));
  }

  public static function missingGroup(string $group): self {
    return new self(sprintf('Missing required group "%s".', $group));
  }

  public static function missingScope(string $scope): self {
    return new self(sprintf('Missing required scope "%s".', $scope));
  }

  public static function wrongTokenUse(string $expected, string $actual): self {
    return new self(sprintf('Token of type "%s" required, got "%s".', $expected, $actual));
  }

}
