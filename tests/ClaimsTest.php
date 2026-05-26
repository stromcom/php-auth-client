<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Stromcom\AuthClient\Claims;
use Stromcom\AuthClient\Exception\AuthorizationException;

final class ClaimsTest extends TestCase {

  public function testUserTokenPayload(): void {
    $claims = Claims::fromPayload([
      'iss'        => 'https://auth.stromcom.cz',
      'sub'        => '42',
      'aud'        => 'cli_abc',
      'iat'        => 1_700_000_000,
      'exp'        => 1_700_000_900,
      'jti'        => 'jti-1',
      'token_use'  => 'user',
      'email'      => 'ja@firma.cz',
      'email_verified' => true,
      'name'        => 'Jan Novák',
      'given_name'  => 'Jan',
      'family_name' => 'Novák',
      'phone_number' => '+420123456789',
      'phone_number_verified' => true,
      'scopes'     => ['openid', 'email', 'groups'],
      'groups'     => ['translate-editor', 'beta'],
      'roles'      => ['auth.admin'],
      'is_admin'   => true,
    ]);

    self::assertTrue($claims->isUser());
    self::assertFalse($claims->isService());
    self::assertSame('42', $claims->subject);
    self::assertSame(['cli_abc'], $claims->audiences);
    self::assertTrue($claims->hasGroup('translate-editor'));
    self::assertFalse($claims->hasGroup('nonexistent'));
    self::assertTrue($claims->hasRole('auth.admin'));
    self::assertTrue($claims->hasScope('email'));
    self::assertTrue($claims->isAdmin);
    self::assertSame('ja@firma.cz', $claims->email);
    self::assertTrue($claims->emailVerified);
    self::assertSame('Jan', $claims->givenName);
    self::assertSame('Novák', $claims->familyName);
    self::assertSame('+420123456789', $claims->phoneNumber);
    self::assertTrue($claims->phoneNumberVerified);
  }

  public function testPersonalClaimsDefaultToNullWhenAbsent(): void {
    $claims = Claims::fromPayload([
      'sub'       => '1',
      'iss'       => 'https://x',
      'token_use' => 'user',
    ]);

    self::assertNull($claims->givenName);
    self::assertNull($claims->familyName);
    self::assertNull($claims->phoneNumber);
    self::assertNull($claims->phoneNumberVerified);
  }

  public function testTokenUseIsNullWhenAbsent(): void {
    $claims = Claims::fromPayload(['sub' => '1', 'iss' => 'https://x']);

    self::assertNull($claims->tokenUse);
    self::assertFalse($claims->isUser());
    self::assertFalse($claims->isService());
  }

  public function testServiceTokenPayload(): void {
    $claims = Claims::fromPayload([
      'iss'         => 'https://auth.stromcom.cz',
      'sub'         => 'svc_ci',
      'aud'         => 'svc_ci',
      'iat'         => 1_700_000_000,
      'exp'         => 1_700_003_600,
      'token_use'   => 'service',
      'client_id'   => 'svc_ci',
      'client_name' => 'ci-bot',
      'roles'       => ['deploy.admin'],
      'is_admin'    => false,
      'scopes'      => 'roles',
    ]);

    self::assertTrue($claims->isService());
    self::assertFalse($claims->isUser());
    self::assertSame('svc_ci', $claims->clientId);
    self::assertSame('ci-bot', $claims->clientName);
    self::assertNull($claims->email);
    self::assertSame(['roles'], $claims->scopes);
    self::assertSame([], $claims->groups);
  }

  public function testAnyAllHelpers(): void {
    $claims = Claims::fromPayload([
      'sub'    => '1',
      'iss'    => 'https://x',
      'roles'  => ['translator.editor', 'deploy.viewer'],
      'groups' => ['beta', 'vip-users'],
    ]);

    self::assertTrue($claims->hasAnyRole('foo.bar', 'translator.editor'));
    self::assertFalse($claims->hasAnyRole('foo.bar', 'foo.baz'));
    self::assertTrue($claims->hasAllRoles('translator.editor', 'deploy.viewer'));
    self::assertFalse($claims->hasAllRoles('translator.editor', 'foo.bar'));
    self::assertFalse($claims->hasAllRoles());

    self::assertTrue($claims->hasAnyGroup('alpha', 'beta'));
    self::assertTrue($claims->hasAllGroups('beta', 'vip-users'));
  }

  public function testRolesForProjectStripsPrefix(): void {
    $claims = Claims::fromPayload([
      'sub'   => '1',
      'iss'   => 'https://x',
      'roles' => ['translator.editor', 'translator.admin', 'deploy.viewer'],
    ]);

    self::assertSame(['editor', 'admin'], $claims->rolesForProject('translator'));
    self::assertTrue($claims->hasProjectRole('translator', 'admin'));
    self::assertFalse($claims->hasProjectRole('translator', 'viewer'));
  }

  public function testRequireMethodsThrowWhenMissing(): void {
    $claims = Claims::fromPayload([
      'sub'       => '1',
      'iss'       => 'https://x',
      'token_use' => 'user',
      'roles'     => ['auth.admin'],
      'groups'    => ['beta'],
      'scopes'    => ['openid'],
    ]);

    $claims->requireRole('auth.admin');
    $claims->requireGroup('beta');
    $claims->requireScope('openid');
    $claims->requireUserToken();

    $this->expectException(AuthorizationException::class);
    $claims->requireServiceToken();
  }

  public function testExpirationHelpers(): void {
    $now = 1_700_000_000;
    $claims = Claims::fromPayload([
      'sub' => '1', 'iss' => 'https://x',
      'iat' => $now - 60, 'exp' => $now + 100,
    ]);

    self::assertFalse($claims->isExpired($now));
    self::assertSame(100, $claims->secondsUntilExpiration($now));
    self::assertTrue($claims->isExpired($now + 200));
    self::assertSame(0, $claims->secondsUntilExpiration($now + 200));
  }

  public function testDisplayNameFallbackChain(): void {
    self::assertSame('Jan',     Claims::fromPayload(['sub' => '1', 'iss' => 'x', 'name' => 'Jan', 'email' => 'a@b'])->displayName());
    self::assertSame('a@b',     Claims::fromPayload(['sub' => '1', 'iss' => 'x', 'email' => 'a@b'])->displayName());
    self::assertSame('ci-bot',  Claims::fromPayload(['sub' => '1', 'iss' => 'x', 'client_name' => 'ci-bot'])->displayName());
    self::assertSame('1',       Claims::fromPayload(['sub' => '1', 'iss' => 'x'])->displayName());
  }

  public function testRawClaimEscapeHatch(): void {
    $claims = Claims::fromPayload(['sub' => '1', 'iss' => 'x', 'custom' => ['a' => 1]]);
    self::assertSame(['a' => 1], $claims->claim('custom'));
    self::assertNull($claims->claim('nope'));
  }

  public function testStringScopeIsSplitOnWhitespace(): void {
    $claims = Claims::fromPayload([
      'sub'    => '1',
      'iss'    => 'https://x',
      'aud'    => ['a', 'b'],
      'scopes' => 'openid  email   groups',
    ]);

    self::assertSame(['openid', 'email', 'groups'], $claims->scopes);
    self::assertSame(['a', 'b'], $claims->audiences);
  }

}
