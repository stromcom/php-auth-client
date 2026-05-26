<?php
declare(strict_types=1);

/**
 * Authorization Code + PKCE — end-to-end web app integration.
 *
 * Single-file PHP that serves:
 *   GET  /login    → redirect user to auth.stromcom.cz
 *   GET  /callback → exchange code for tokens, set cookies, redirect to /api
 *   GET  /api      → verify Bearer JWT via JWKS, print user info
 *   GET  /logout   → clear local cookies, redirect to end_session_endpoint
 *
 * Run with:
 *   AUTH_ISSUER=http://localhost:8003 \
 *   AUTH_CLIENT_ID=cli_xxx AUTH_CLIENT_SECRET=... \
 *   php -S localhost:9000 examples/web-app-callback.php
 *
 * Register a client first with redirect URI http://localhost:9000/callback.
 */

require __DIR__ . '/../vendor/autoload.php';

use Stromcom\AuthClient\Client;
use Stromcom\AuthClient\Configuration;
use Stromcom\AuthClient\Exception\OAuthServerException;
use Stromcom\AuthClient\Exception\TokenVerificationException;
use Stromcom\AuthClient\Jwks\FileJwksCache;

session_start();

$auth = new Client(
  new Configuration(
    clientId:     getenv('AUTH_CLIENT_ID') ?: 'cli_xxxxxxxxxxxxxxxx',
    clientSecret: getenv('AUTH_CLIENT_SECRET') ?: null,
    redirectUri:  'http://localhost:9000/callback',
    issuer:       getenv('AUTH_ISSUER') ?: 'http://localhost:8003',
  ),
  jwksCache: new FileJwksCache(sys_get_temp_dir() . '/stromcom-auth-jwks'),
);

$path = parse_url((string) $_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';

if ($path === '/login') {
  [$url, $pkce, $state, $nonce] = $auth->beginAuthorization();
  $_SESSION['oauth_verifier'] = $pkce->verifier;
  $_SESSION['oauth_state']    = $state;
  $_SESSION['oauth_nonce']    = $nonce;
  header('Location: ' . $url);
  exit;
}

if ($path === '/callback') {
  $code  = $_GET['code']  ?? null;
  $state = $_GET['state'] ?? null;

  if (!is_string($code) || !is_string($state) || !hash_equals((string) ($_SESSION['oauth_state'] ?? ''), $state)) {
    http_response_code(400);
    exit('Invalid state — possible CSRF.');
  }

  try {
    $tokens = $auth->exchangeCode($code, (string) ($_SESSION['oauth_verifier'] ?? ''));
  } catch (OAuthServerException $e) {
    http_response_code(401);
    exit('OAuth error: ' . $e->errorCode);
  }

  unset($_SESSION['oauth_verifier'], $_SESSION['oauth_state']);

  setcookie('access_token', $tokens->accessToken, [
    'expires'  => $tokens->expiresAt,
    'path'     => '/',
    'secure'   => !empty($_SERVER['HTTPS']),
    'httponly' => true,
    'samesite' => 'Lax',
  ]);
  if ($tokens->refreshToken !== null) {
    setcookie('refresh_token', $tokens->refreshToken, [
      'expires'  => time() + 14 * 24 * 3600,
      'path'     => '/',
      'secure'   => !empty($_SERVER['HTTPS']),
      'httponly' => true,
      'samesite' => 'Strict',
    ]);
  }

  header('Location: /api');
  exit;
}

if ($path === '/api') {
  $accessToken = $_COOKIE['access_token'] ?? null;
  if (!is_string($accessToken)) {
    header('Location: /login');
    exit;
  }

  try {
    $claims = $auth->verify($accessToken);
  } catch (TokenVerificationException) {
    header('Location: /login');
    exit;
  }

  header('Content-Type: application/json');
  echo json_encode([
    'sub'       => $claims->subject,
    'email'     => $claims->email,
    'name'      => $claims->name,
    'groups'    => $claims->groups,
    'roles'     => $claims->roles,
    'is_admin'  => $claims->isAdmin,
    'token_use' => $claims->tokenUse,
  ], JSON_PRETTY_PRINT);
  exit;
}

if ($path === '/logout') {
  setcookie('access_token',  '', ['expires' => 1, 'path' => '/']);
  setcookie('refresh_token', '', ['expires' => 1, 'path' => '/']);
  session_destroy();
  header('Location: ' . $auth->logoutUrl('http://localhost:9000/'));
  exit;
}

echo '<a href="/login">Login</a>';
