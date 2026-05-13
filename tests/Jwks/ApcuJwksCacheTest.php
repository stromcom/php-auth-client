<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Tests\Jwks;

use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Stromcom\AuthClient\Exception\ConfigurationException;
use Stromcom\AuthClient\Jwks\ApcuJwksCache;

final class ApcuJwksCacheTest extends TestCase {

  public function testConstructorRejectsMissingApcu(): void {
    if (function_exists('apcu_enabled') && apcu_enabled()) {
      self::markTestSkipped('APCu is loaded — this test covers the fallback path.');
    }

    $this->expectException(ConfigurationException::class);
    new ApcuJwksCache();
  }

  #[RequiresPhpExtension('apcu')]
  public function testRoundTrip(): void {
    if (!apcu_enabled()) {
      self::markTestSkipped('APCu is loaded but disabled (apc.enable_cli=0).');
    }

    $cache = new ApcuJwksCache(keyPrefix: 'jwks_test_');
    $cache->set('https://example/jwks.json', ['keys' => [['kid' => 'abc']]], 60);

    $loaded = $cache->get('https://example/jwks.json');

    self::assertIsArray($loaded);
    self::assertSame([['kid' => 'abc']], $loaded['keys']);
  }

  #[RequiresPhpExtension('apcu')]
  public function testDeleteRemovesEntry(): void {
    if (!apcu_enabled()) {
      self::markTestSkipped('APCu is loaded but disabled (apc.enable_cli=0).');
    }

    $cache = new ApcuJwksCache(keyPrefix: 'jwks_test_del_');
    $cache->set('k', ['keys' => []], 60);
    $cache->delete('k');

    self::assertNull($cache->get('k'));
  }

}
