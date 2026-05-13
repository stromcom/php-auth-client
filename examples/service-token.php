<?php
declare(strict_types=1);

/**
 * Machine-to-machine: fetch a service token and call an internal API.
 *
 * Run with:
 *   AUTH_CLIENT_ID=svc_... AUTH_CLIENT_SECRET=... php examples/service-token.php
 */

require __DIR__ . '/../vendor/autoload.php';

use Stromcom\AuthClient\Client;
use Stromcom\AuthClient\Configuration;
use Stromcom\AuthClient\Exception\OAuthServerException;

$auth = new Client(
  new Configuration(
    clientId:     (string) getenv('AUTH_CLIENT_ID'),
    clientSecret: (string) getenv('AUTH_CLIENT_SECRET'),
    issuer:       getenv('AUTH_ISSUER') ?: 'http://localhost:8003',
  ),
);

try {
  $tokens = $auth->clientCredentials();
} catch (OAuthServerException $e) {
  fwrite(STDERR, sprintf("token error: %s — %s\n", $e->errorCode, $e->errorDescription ?? ''));
  exit(1);
}

echo "access_token  : {$tokens->accessToken}\n";
echo "expires_in    : {$tokens->expiresIn}s\n";
echo "authorization : {$tokens->authorizationHeader()}\n";

$claims = $auth->verify($tokens->accessToken);
echo "client_id     : {$claims->clientId}\n";
echo "client_name   : {$claims->clientName}\n";
echo 'roles         : ' . implode(', ', $claims->roles) . "\n";
echo "token_use     : {$claims->tokenUse}\n";
