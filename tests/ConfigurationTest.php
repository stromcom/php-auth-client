<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Stromcom\AuthClient\Configuration;
use Stromcom\AuthClient\Exception\ConfigurationException;

final class ConfigurationTest extends TestCase {

  public function testDefaultEndpointsDerivedFromIssuer(): void {
    $cfg = new Configuration(clientId: 'cli_abc', issuer: 'https://auth.example.com/');

    self::assertSame('https://auth.example.com', $cfg->issuer);
    self::assertSame('https://auth.example.com/oauth/authorize', $cfg->authorizationEndpoint);
    self::assertSame('https://auth.example.com/oauth/token', $cfg->tokenEndpoint);
    self::assertSame('https://auth.example.com/me', $cfg->userInfoEndpoint);
    self::assertSame('https://auth.example.com/oauth/logout', $cfg->logoutEndpoint);
    self::assertSame('https://auth.example.com/.well-known/jwks.json', $cfg->jwksUri);
  }

  public function testEndpointsCanBeOverridden(): void {
    $cfg = new Configuration(
      clientId:              'cli_abc',
      issuer:                'https://issuer.example.com',
      authorizationEndpoint: 'https://auth.example.com/login',
      tokenEndpoint:         'https://auth.example.com/token',
    );

    self::assertSame('https://auth.example.com/login', $cfg->authorizationEndpoint);
    self::assertSame('https://auth.example.com/token', $cfg->tokenEndpoint);
    self::assertSame('https://issuer.example.com/me', $cfg->userInfoEndpoint);
  }

  public function testEmptyClientIdIsRejected(): void {
    $this->expectException(ConfigurationException::class);
    new Configuration(clientId: '');
  }

  public function testRequireRedirectUriThrowsWhenMissing(): void {
    $cfg = new Configuration(clientId: 'cli_abc');
    $this->expectException(ConfigurationException::class);
    $cfg->requireRedirectUri();
  }

  public function testRequireClientSecretThrowsWhenMissing(): void {
    $cfg = new Configuration(clientId: 'cli_abc');
    $this->expectException(ConfigurationException::class);
    $cfg->requireClientSecret();
  }

}
