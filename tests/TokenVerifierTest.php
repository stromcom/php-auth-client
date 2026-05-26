<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Tests;

use PHPUnit\Framework\TestCase;
use Stromcom\AuthClient\Configuration;
use Stromcom\AuthClient\Exception\TokenVerificationException;
use Stromcom\AuthClient\Http\HttpClientInterface;
use Stromcom\AuthClient\Http\RawResponse;
use Stromcom\AuthClient\Jwks\InMemoryJwksCache;
use Stromcom\AuthClient\TokenVerifier;

/**
 * Surface-level guard tests for the two verifier entry points. End-to-end
 * crypto coverage (real signature verification against baked JWKS) lives
 * outside this unit test — see `examples/smoke.php` for the integration check.
 */
final class TokenVerifierTest extends TestCase {

  public function testVerifyRejectsEmptyJwt(): void {
    $verifier = $this->verifier();

    $this->expectException(TokenVerificationException::class);
    $this->expectExceptionMessage('JWT is empty.');
    $verifier->verify('', 'cli_abc');
  }

  public function testVerifyRejectsEmptyAudience(): void {
    $verifier = $this->verifier();

    $this->expectException(TokenVerificationException::class);
    $this->expectExceptionMessage('Expected audience');
    $verifier->verify('eyJ.x.y', '');
  }

  public function testVerifyIdTokenRejectsEmptyNonce(): void {
    $verifier = $this->verifier();

    $this->expectException(TokenVerificationException::class);
    $this->expectExceptionMessage('Expected nonce');
    $verifier->verifyIdToken('eyJ.x.y', '');
  }

  private function verifier(): TokenVerifier {
    return new TokenVerifier(
      new Configuration(clientId: 'cli_abc', issuer: 'https://auth.example'),
      new class implements HttpClientInterface {
        public function request(string $method, string $url, array $headers = [], ?string $body = null): RawResponse {
          throw new \RuntimeException('Network not expected in unit tests.');
        }
      },
      new InMemoryJwksCache(),
    );
  }

}
