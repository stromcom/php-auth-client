<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Jwks;

use Stromcom\AuthClient\Exception\ConfigurationException;

final class FileJwksCache implements JwksCacheInterface {

  public function __construct(
    public readonly string $directory,
  ) {
    if (!is_dir($directory)) {
      if (!@mkdir($directory, 0o700, true) && !is_dir($directory)) {
        throw new ConfigurationException("Could not create JWKS cache directory: {$directory}");
      }
    }
    if (!is_writable($directory)) {
      throw new ConfigurationException("JWKS cache directory is not writable: {$directory}");
    }
  }

  public function get(string $key): ?array {
    $path = $this->path($key);
    if (!is_file($path)) {
      return null;
    }
    $raw = @file_get_contents($path);
    if ($raw === false) {
      return null;
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded) || !isset($decoded['expiresAt'], $decoded['jwks']) || !is_int($decoded['expiresAt']) || !is_array($decoded['jwks'])) {
      return null;
    }
    if ($decoded['expiresAt'] <= time()) {
      @unlink($path);
      return null;
    }
    /** @var array<string, mixed> $jwks */
    $jwks = $decoded['jwks'];
    return $jwks;
  }

  public function set(string $key, array $jwks, int $ttlSeconds): void {
    $path = $this->path($key);
    $payload = json_encode([
      'expiresAt' => time() + $ttlSeconds,
      'jwks'      => $jwks,
    ]);
    if ($payload === false) {
      return;
    }
    @file_put_contents($path, $payload, LOCK_EX);
    @chmod($path, 0o600);
  }

  public function delete(string $key): void {
    $path = $this->path($key);
    if (is_file($path)) {
      @unlink($path);
    }
  }

  private function path(string $key): string {
    return rtrim($this->directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'jwks_' . sha1($key) . '.json';
  }

}
