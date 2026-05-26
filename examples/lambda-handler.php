<?php
declare(strict_types=1);

/**
 * AWS Lambda + Bref handler that verifies an inbound Bearer JWT.
 *
 * Caching strategy on Lambda:
 *
 *  - APCu (kernel shared memory): visible to every PHP-FPM worker in the
 *    same Lambda container. Survives warm invocations for the lifetime of
 *    the container. THIS IS THE RIGHT DEFAULT for Bref `php-fpm` runtime.
 *
 *  - In-memory (per-process): only works if you keep the `Client` instance
 *    in a top-level static, AND each FPM worker fetches its own JWKS on
 *    first use. Lower hit rate than APCu when the container has >1 worker.
 *
 *  - File cache (`/tmp/...`): also works (Lambda's /tmp is container-scoped
 *    and writable), but the only real reason to use it over APCu is if
 *    you've explicitly disabled APCu.
 *
 * The handler keeps the `Client` in a static so it's reused across warm
 * invocations of the same container.
 */

require __DIR__ . '/../vendor/autoload.php';

use Stromcom\AuthClient\Client;
use Stromcom\AuthClient\Configuration;
use Stromcom\AuthClient\Exception\AuthorizationException;
use Stromcom\AuthClient\Exception\TokenVerificationException;
use Stromcom\AuthClient\Jwks\ApcuJwksCache;
use Stromcom\AuthClient\Jwks\InMemoryJwksCache;
use Stromcom\AuthClient\Jwks\JwksCacheInterface;

/**
 * Lazy singleton — instantiated once per Lambda container, reused across
 * warm invocations.
 */
function auth(): Client {
  static $client = null;
  if ($client === null) {
    $client = new Client(
      new Configuration(
        clientId: (string) getenv('AUTH_CLIENT_ID'),
        issuer:   getenv('AUTH_ISSUER') ?: 'https://auth.stromcom.cz',
      ),
      jwksCache: jwksCache(),
    );
  }
  return $client;
}

function jwksCache(): JwksCacheInterface {
  if (function_exists('apcu_enabled') && apcu_enabled()) {
    return new ApcuJwksCache();
  }
  // Fallback: per-process memory. Still survives warm invocations because
  // the Client is held in a static.
  return new InMemoryJwksCache();
}

/**
 * Bref-style API Gateway handler.
 *
 * In serverless.yml:
 *   functions:
 *     api:
 *       handler: examples/lambda-handler.php
 *       runtime: php-84-fpm
 *
 * @param array<string, mixed> $event
 * @return array<string, mixed>
 */
return static function (array $event): array {
  $authHeader = (string) (
    $event['headers']['authorization']
    ?? $event['headers']['Authorization']
    ?? ''
  );
  if (!preg_match('/^Bearer\s+(.+)$/i', $authHeader, $m)) {
    return response(401, ['error' => 'missing_bearer_token']);
  }

  try {
    $claims = auth()->verify($m[1], auth()->configuration->clientId);
    $claims->requireUserToken();
    $claims->requireGroup('translate-editor');
  } catch (TokenVerificationException $e) {
    return response(401, ['error' => 'invalid_token', 'message' => $e->getMessage()]);
  } catch (AuthorizationException $e) {
    return response(403, ['error' => 'forbidden', 'message' => $e->getMessage()]);
  }

  return response(200, [
    'subject' => $claims->subject,
    'email'   => $claims->email,
    'groups'  => $claims->groups,
  ]);
};

/**
 * @param array<string, mixed> $body
 * @return array<string, mixed>
 */
function response(int $status, array $body): array {
  return [
    'statusCode' => $status,
    'headers'    => ['Content-Type' => 'application/json'],
    'body'       => json_encode($body, JSON_UNESCAPED_SLASHES),
  ];
}
