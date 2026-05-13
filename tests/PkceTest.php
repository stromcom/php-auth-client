<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Stromcom\AuthClient\Pkce;

final class PkceTest extends TestCase {

  public function testGenerateProducesUrlSafeValues(): void {
    $pkce = Pkce::generate();

    self::assertSame('S256', $pkce->method);
    self::assertMatchesRegularExpression('/^[A-Za-z0-9_\-]{43,}$/', $pkce->verifier);
    self::assertMatchesRegularExpression('/^[A-Za-z0-9_\-]{43}$/', $pkce->challenge);
    self::assertStringNotContainsString('=', $pkce->verifier);
    self::assertStringNotContainsString('=', $pkce->challenge);
  }

  public function testChallengeIsSha256OfVerifier(): void {
    $pkce = Pkce::generate();
    self::assertSame($pkce->challenge, Pkce::challengeFor($pkce->verifier));
  }

  public function testGenerateProducesDistinctPairs(): void {
    self::assertNotSame(Pkce::generate()->verifier, Pkce::generate()->verifier);
  }

}
