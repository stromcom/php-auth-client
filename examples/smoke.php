<?php
declare(strict_types=1);

/**
 * Local smoke test against a running auth server.
 *
 * Prerequisites:
 *   - a reachable auth.stromcom.cz instance (production or a dev deployment)
 *   - a service-account client (svc_…) and its secret
 *
 * Run with:
 *   AUTH_ISSUER=https://auth.stromcom.cz \
 *   AUTH_CLIENT_ID=svc_... \
 *   AUTH_CLIENT_SECRET=... \
 *   php examples/smoke.php
 */

require __DIR__ . '/../vendor/autoload.php';

use Stromcom\AuthClient\Client;
use Stromcom\AuthClient\Configuration;

$clientId = getenv('AUTH_CLIENT_ID');
$clientSecret = getenv('AUTH_CLIENT_SECRET');
if ($clientId === false || $clientSecret === false || $clientId === '' || $clientSecret === '') {
  fwrite(STDERR, "Set AUTH_CLIENT_ID and AUTH_CLIENT_SECRET.\n");
  exit(2);
}

$auth = new Client(new Configuration(
  clientId:     $clientId,
  clientSecret: $clientSecret,
  issuer:       getenv('AUTH_ISSUER') ?: 'http://localhost:8003',
));

echo "1) GET /.well-known/openid-configuration\n";
$discovery = $auth->discover();
printf("   issuer=%s\n   token_endpoint=%s\n", $discovery['issuer'] ?? '?', $discovery['token_endpoint'] ?? '?');

echo "\n2) POST /oauth/token (client_credentials)\n";
$tokens = $auth->clientCredentials();
printf("   expires_in=%d  jwt_prefix=%s\n", $tokens->expiresIn, substr($tokens->accessToken, 0, 40) . '...');

echo "\n3) Local JWT verification via JWKS\n";
$claims = $auth->verify($tokens->accessToken, $auth->configuration->clientId);
printf("   sub=%s\n   aud=[%s]\n   token_use=%s  isService=%s\n   displayName=%s\n",
  $claims->subject,
  implode(',', $claims->audiences),
  $claims->tokenUse ?? '(none)',
  $claims->isService() ? 'yes' : 'no',
  $claims->displayName(),
);

echo "\n4) GET /me\n";
$me = $auth->userInfo($tokens->accessToken);
printf("   client_name=%s  roles=[%s]\n",
  is_string($me['client_name'] ?? null) ? $me['client_name'] : '?',
  is_array($me['roles'] ?? null) ? implode(',', array_map('strval', $me['roles'])) : '',
);

echo "\nOK\n";
