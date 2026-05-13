<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Jwks;

use Stromcom\AuthClient\Exception\ConfigurationException;

/**
 * APCu-backed JWKS cache. The right choice for AWS Lambda (Bref `php-fpm`
 * runtime) and traditional PHP-FPM deployments — entries live in kernel
 * shared memory and are visible to every PHP-FPM worker in the same
 * container/host. Survives across requests for the lifetime of the
 * Lambda container / FPM process pool.
 *
 * Requirements: `ext-apcu` loaded and enabled. Bref's php-fpm layers enable
 * it by default; for local CLI you may need `apc.enable_cli=1`.
 */
final class ApcuJwksCache implements JwksCacheInterface {

  public function __construct(
    public readonly string $keyPrefix = 'stromcom_auth_jwks_',
  ) {
    if (!function_exists('apcu_enabled') || !apcu_enabled()) {
      throw new ConfigurationException(
        'APCu is not loaded or not enabled — cannot use ApcuJwksCache. '
        . 'Install ext-apcu, or fall back to InMemoryJwksCache.',
      );
    }
  }

  public function get(string $key): ?array {
    $success = false;
    $value = apcu_fetch($this->prefixed($key), $success);
    if (!$success || !is_array($value)) {
      return null;
    }
    /** @var array<string, mixed> $value */
    return $value;
  }

  public function set(string $key, array $jwks, int $ttlSeconds): void {
    apcu_store($this->prefixed($key), $jwks, $ttlSeconds);
  }

  public function delete(string $key): void {
    apcu_delete($this->prefixed($key));
  }

  private function prefixed(string $key): string {
    return $this->keyPrefix . sha1($key);
  }

}
