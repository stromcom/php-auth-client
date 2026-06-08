<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Internal;

use Stromcom\AuthClient\Exception\TokenVerificationException;

/**
 * Builds a PEM-encoded RSA public key from a JWK (`kty=RSA`, `n`, `e`).
 *
 * lcobucci/jwt accepts only PEM-encoded keys via `InMemory::plainText()`;
 * JWKS publishes JWK-encoded keys. This builder bridges the two formats by
 * emitting the standard ASN.1 DER SubjectPublicKeyInfo wrapping.
 *
 * @internal
 */
final class JwkRsaKey {

  /**
   * @param array<string, mixed> $jwk
   * @return non-empty-string
   */
  public static function toPem(array $jwk): string {
    if (($jwk['kty'] ?? null) !== 'RSA') {
      throw new TokenVerificationException('Only RSA JWKs are supported (kty must be "RSA").');
    }
    if (!isset($jwk['n'], $jwk['e']) || !is_string($jwk['n']) || !is_string($jwk['e'])) {
      throw new TokenVerificationException('JWK is missing "n" or "e".');
    }

    $modulus = self::encodeInteger(self::base64UrlDecode($jwk['n']));
    $exponent = self::encodeInteger(self::base64UrlDecode($jwk['e']));

    $rsaPublicKey = self::encodeSequence($modulus . $exponent);
    $bitString = self::encodeBitString($rsaPublicKey);

    $oid = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
    $subjectPublicKeyInfo = self::encodeSequence($oid . $bitString);

    return "-----BEGIN PUBLIC KEY-----\n"
      . chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n")
      . "-----END PUBLIC KEY-----\n";
  }

  private static function base64UrlDecode(string $value): string {
    $padded = strtr($value, '-_', '+/');
    $padLength = (4 - (strlen($padded) % 4)) % 4;
    if ($padLength > 0) {
      $padded .= str_repeat('=', $padLength);
    }
    $decoded = base64_decode($padded, true);
    if ($decoded === false) {
      throw new TokenVerificationException('Invalid base64url input in JWK.');
    }
    return $decoded;
  }

  private static function encodeInteger(string $bytes): string {
    $bytes = ltrim($bytes, "\x00");
    if ($bytes === '') {
      $bytes = "\x00";
    }
    if ((ord($bytes[0]) & 0x80) !== 0) {
      $bytes = "\x00" . $bytes;
    }
    return "\x02" . self::encodeLength(strlen($bytes)) . $bytes;
  }

  private static function encodeSequence(string $bytes): string {
    return "\x30" . self::encodeLength(strlen($bytes)) . $bytes;
  }

  private static function encodeBitString(string $bytes): string {
    return "\x03" . self::encodeLength(strlen($bytes) + 1) . "\x00" . $bytes;
  }

  /** @param int<0, max> $length */
  private static function encodeLength(int $length): string {
    if ($length < 0x80) {
      return chr($length);
    }
    $bytes = '';
    while ($length > 0) {
      $bytes = chr($length & 0xff) . $bytes;
      $length >>= 8;
    }
    return chr((0x80 | strlen($bytes)) & 0xff) . $bytes;
  }

}
