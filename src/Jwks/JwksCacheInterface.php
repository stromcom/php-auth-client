<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Jwks;

interface JwksCacheInterface {

  /**
   * @return array<string, mixed>|null Parsed JWKS document, or null if missing/stale.
   */
  public function get(string $key): ?array;

  /**
   * @param array<string, mixed> $jwks
   */
  public function set(string $key, array $jwks, int $ttlSeconds): void;

  public function delete(string $key): void;

}
