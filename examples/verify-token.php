<?php
declare(strict_types=1);

/**
 * Resource-server pattern: verify the Bearer JWT on every inbound request.
 *
 * No user login flow — this is the pattern for an internal API that accepts
 * tokens issued elsewhere. Apply per-endpoint authorization on top.
 */

require __DIR__ . '/../vendor/autoload.php';

use Stromcom\AuthClient\Client;
use Stromcom\AuthClient\Configuration;
use Stromcom\AuthClient\Exception\AuthorizationException;
use Stromcom\AuthClient\Exception\TokenVerificationException;
use Stromcom\AuthClient\Jwks\FileJwksCache;

$auth = new Client(
  new Configuration(
    clientId: (string) getenv('AUTH_CLIENT_ID'),
    issuer:   getenv('AUTH_ISSUER') ?: 'http://localhost:8003',
  ),
  jwksCache: new FileJwksCache(sys_get_temp_dir() . '/stromcom-auth-jwks'),
);

$header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (!preg_match('/^Bearer\s+(.+)$/i', $header, $m)) {
  http_response_code(401);
  header('WWW-Authenticate: Bearer realm="api"');
  exit(json_encode(['error' => 'missing_bearer_token']));
}

try {
  $claims = $auth->verify($m[1], $auth->configuration->clientId);
  $claims->requireGroup('translate-editor');
} catch (TokenVerificationException $e) {
  http_response_code(401);
  exit(json_encode(['error' => 'invalid_token', 'message' => $e->getMessage()]));
} catch (AuthorizationException $e) {
  http_response_code(403);
  exit(json_encode(['error' => 'forbidden', 'message' => $e->getMessage()]));
}

header('Content-Type: application/json');
echo json_encode([
  'subject' => $claims->subject,
  'email'   => $claims->email,
  'groups'  => $claims->groups,
]);
