<?php
declare(strict_types=1);

/**
 * Long-running service account worker that caches its token across calls.
 *
 * Re-fetching a token on every downstream call wastes ~10 ms each time. For
 * a worker that runs for hours, cache the TokenSet and refresh it only when
 * it nears expiry.
 *
 * Run with:
 *   AUTH_CLIENT_ID=svc_... AUTH_CLIENT_SECRET=... php examples/service-account-cached.php
 */

require __DIR__ . '/../vendor/autoload.php';

use Stromcom\AuthClient\Client;
use Stromcom\AuthClient\Configuration;
use Stromcom\AuthClient\TokenSet;

final class ServiceTokenCache {

  private ?TokenSet $current = null;

  public function __construct(
    private readonly Client $auth,
    private readonly int $refreshLeewaySeconds = 60,
  ) {}

  public function get(): TokenSet {
    $now = time();
    if ($this->current === null || $this->current->isExpired($now, $this->refreshLeewaySeconds)) {
      $this->current = $this->auth->clientCredentials();
    }
    return $this->current;
  }
}

$auth = new Client(new Configuration(
  clientId:     (string) getenv('AUTH_CLIENT_ID'),
  clientSecret: (string) getenv('AUTH_CLIENT_SECRET'),
  issuer:       getenv('AUTH_ISSUER') ?: 'http://localhost:8003',
));

$tokenCache = new ServiceTokenCache($auth, refreshLeewaySeconds: 60);

// Simulate a worker doing 5 calls to a downstream API.
for ($i = 1; $i <= 5; $i++) {
  $tokens = $tokenCache->get();
  echo sprintf(
    "[%d] using token expiring in %d s\n",
    $i,
    $tokens->expiresAt - time(),
  );
  // $http->get('https://api.stromcom.cz/v1/things', [
  //     'headers' => ['Authorization' => $tokens->authorizationHeader()],
  // ]);
  sleep(1);
}
