<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Jwks;

final class InMemoryJwksCache implements JwksCacheInterface {

  /** @var array<string, array{jwks: array<string, mixed>, expiresAt: int}> */
  private array $store = [];

  public function get(string $key): ?array {
    $entry = $this->store[$key] ?? null;
    if ($entry === null) {
      return null;
    }
    if ($entry['expiresAt'] <= time()) {
      unset($this->store[$key]);
      return null;
    }
    return $entry['jwks'];
  }

  public function set(string $key, array $jwks, int $ttlSeconds): void {
    $this->store[$key] = [
      'jwks'      => $jwks,
      'expiresAt' => time() + $ttlSeconds,
    ];
  }

  public function delete(string $key): void {
    unset($this->store[$key]);
  }

}
