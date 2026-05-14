# stromcom/auth-client

Official PHP client for the STROMCOM SSO server (**auth.stromcom.cz**).
Implements OAuth 2.0 Authorization Code + PKCE, Client Credentials, JWT
verification via JWKS with caching, UserInfo and logout. No framework
dependencies, zero external JWT libraries.

> **Status:** stable. RFC 9068 strict (requires `iss`, `token_use`, `at+jwt`).
>
> Default issuer points to `https://auth.stromcom.cz`. For local development
> against a dev auth server, override `issuer` accordingly.

---

## Installation

```bash
composer require stromcom/auth-client
```

**Requirements:** PHP 8.3+, `ext-curl`, `ext-json`, `ext-openssl`.

**Runtime dependencies:** `lcobucci/jwt` (and its transitive `psr/clock`).
That's it — no Guzzle, no PSR-7, no framework integration.
JWT parsing, signature verification and temporal-claim checks go through
`lcobucci/jwt`; JWKS fetching, caching, key-rotation orchestration and the
OAuth grant flows are in-house.

---

## Quickstart

```php
use Stromcom\AuthClient\Client;
use Stromcom\AuthClient\Configuration;

$auth = new Client(new Configuration(
    clientId:     getenv('AUTH_CLIENT_ID'),
    clientSecret: getenv('AUTH_CLIENT_SECRET'),
    redirectUri:  'https://my-app.stromcom.cz/oauth/callback',
));
```

### Web application — user login

```php
// 1. Anywhere a protected page needs auth — start the flow.
session_start();
[$url, $pkce, $state] = $auth->beginAuthorization();
$_SESSION['oauth_verifier'] = $pkce->verifier;
$_SESSION['oauth_state']    = $state;
header('Location: ' . $url);

// 2. In your /oauth/callback handler — validate state, exchange code.
if (!hash_equals($_SESSION['oauth_state'], $_GET['state'])) {
    exit('CSRF');
}
$tokens = $auth->exchangeCode($_GET['code'], $_SESSION['oauth_verifier']);

// 3. Per request — verify the bearer JWT (JWKS is cached for 1 h).
$claims = $auth->verify($tokens->accessToken);
if ($claims->hasGroup('translate-editor')) {
    // authorize
}
```

Full walkthrough: [docs/auth-code-flow.md](docs/auth-code-flow.md).

### Service account — machine-to-machine

```php
$auth = new Client(new Configuration(
    clientId:     'svc_ci_xxxxx',
    clientSecret: getenv('AUTH_CLIENT_SECRET'),
));

$tokens = $auth->clientCredentials();

$response = $http->get('https://api.stromcom.cz/v1/things', [
    'headers' => ['Authorization' => $tokens->authorizationHeader()],
]);
```

For long-running processes, cache the token until it nears expiry — see
[examples/service-account-cached.php](examples/service-account-cached.php).
Full walkthrough: [docs/service-account.md](docs/service-account.md).

### Refresh

```php
$tokens = $auth->refresh($oldRefreshToken);
// The server rotates: the OLD refresh token is invalidated immediately.
// Persist $tokens->refreshToken right away.
```

### Logout

```php
header('Location: ' . $auth->logoutUrl('https://my-app.stromcom.cz/'));
```

Logout clears the SSO session cookie on auth.stromcom.cz. Tokens you already
issued remain valid until their `exp` — clear your own cookies too.

---

## Claims — object API

`$auth->verify($jwt)` returns a `Claims` value object. Don't dig into the raw
payload — use the rich API:

```php
$claims = $auth->verify($jwt);

// Identity
$claims->subject;              // sub
$claims->email;                // ?string
$claims->emailVerified;        // ?bool
$claims->name;                 // ?string (display name, scope `profile`)
$claims->givenName;            // ?string (scope `profile`)
$claims->familyName;           // ?string (scope `profile`)
$claims->phoneNumber;          // ?string E.164 (scope `phone`)
$claims->phoneNumberVerified;  // ?bool   (scope `phone`)
$claims->isAdmin;              // bool
$claims->displayName();        // name → email → client_name → sub
$claims->audience();           // first aud
$claims->isExpired();
$claims->secondsUntilExpiration();

// User vs service tokens
$claims->isUser();             // token_use=user
$claims->isService();          // token_use=service
$claims->clientId;             // service token only
$claims->clientName;           // service token only

// Roles (project-scoped: "{prefix}.{role}")
$claims->roles;                                  // list<string>
$claims->hasRole('translator.editor');
$claims->hasAnyRole('translator.editor', 'translator.admin');
$claims->hasAllRoles('deploy.admin', 'deploy.viewer');
$claims->hasProjectRole('translator', 'editor'); // == hasRole('translator.editor')
$claims->rolesForProject('translator');          // ['editor', 'admin']  (prefix stripped)

// Groups (free-form labels)
$claims->groups;
$claims->hasGroup('vip-users');
$claims->hasAnyGroup('beta', 'early-access');
$claims->hasAllGroups('beta', 'vip-users');

// Scopes
$claims->scopes;
$claims->hasScope('email');

// Guard helpers — throw AuthorizationException if missing
$claims->requireRole('translator.editor');
$claims->requireAnyRole('translator.editor', 'translator.admin');
$claims->requireGroup('vip-users');
$claims->requireScope('email');
$claims->requireUserToken();    // throws if a service token was presented
$claims->requireServiceToken();

// Escape hatch for non-standard claims
$claims->claim('custom_thing');
$claims->all; // raw payload
```

Full reference: [docs/jwt-verification.md](docs/jwt-verification.md).

---

## Configuration

| Parameter       | Default                                  | Description                                                  |
|-----------------|------------------------------------------|--------------------------------------------------------------|
| `clientId`      | (required)                               | `cli_…` / `svc_…` issued in the admin UI                     |
| `clientSecret`  | `null`                                   | Required for confidential clients & `client_credentials`     |
| `redirectUri`   | `null`                                   | Required for `authorization_code`                            |
| `issuer`        | `https://auth.stromcom.cz`               | Server base URL — for local dev use `http://localhost:8003`  |
| `defaultScopes` | `['openid','profile','email','groups']`  | Used when `beginAuthorization()` is called without `$scopes` |
| `timeout`       | `10`                                     | HTTP timeout in seconds                                      |
| `jwksTtl`       | `3600`                                   | JWKS cache TTL in seconds                                    |
| `leeway`        | `30`                                     | JWT clock-skew tolerance in seconds                          |
| `userAgent`     | `stromcom-auth-client-php/1.0`           | Sent on every outbound request                               |

Endpoints are derived from `issuer`. To override (rare — e.g. a reverse
proxy), pass `authorizationEndpoint`, `tokenEndpoint`, `userInfoEndpoint`,
`logoutEndpoint`, `jwksUri` explicitly.

---

## JWKS caching

The server publishes `Cache-Control: max-age=3600` on `/.well-known/jwks.json`.
The verifier caches the document so per-request verification does not call the
auth server. Pick the backend that matches your runtime:

| Backend                 | Use it for                                                   |
|-------------------------|--------------------------------------------------------------|
| `InMemoryJwksCache`     | Per-process. CLI scripts. Long-running workers (RoadRunner). |
| `ApcuJwksCache`         | **AWS Lambda (Bref) + any PHP-FPM** — shared memory, fastest |
| `FileJwksCache`         | Single-host without APCu (rare)                              |

```php
use Stromcom\AuthClient\Jwks\ApcuJwksCache;     // Lambda / FPM
use Stromcom\AuthClient\Jwks\InMemoryJwksCache; // CLI / workers
use Stromcom\AuthClient\Jwks\FileJwksCache;     // fallback

$auth = new Client($configuration, jwksCache: new ApcuJwksCache());
```

Implement `JwksCacheInterface` for Redis/Memcached/PSR-16 backends. On `kid`
miss the cache is invalidated and re-fetched once automatically — that's
how key rotation works without restart.

---

## Exceptions

| Class                          | When                                                                          |
|--------------------------------|-------------------------------------------------------------------------------|
| `ConfigurationException`       | Missing required field in `Configuration`                                     |
| `TransportException`           | Network failure (cURL error, DNS, TLS, timeout)                               |
| `OAuthServerException`         | Auth server returned an `error` (e.g. `invalid_grant`, `invalid_client`).     |
| `TokenVerificationException`   | JWT signature / `iss` / `aud` / `exp` / `token_use` validation failed         |
| `AuthorizationException`       | Missing role / group / scope, wrong `token_use`                               |
| `AuthClientException`          | Base — catch this for anything thrown by the SDK                              |

Full mapping with retry guidance: [docs/error-handling.md](docs/error-handling.md).

---

## Examples

| File                                                                            | Demonstrates                                       |
|---------------------------------------------------------------------------------|----------------------------------------------------|
| [examples/web-app-callback.php](examples/web-app-callback.php)                  | Full auth-code+PKCE flow (login / callback / api / logout) |
| [examples/service-token.php](examples/service-token.php)                        | M2M client_credentials, one-shot                   |
| [examples/service-account-cached.php](examples/service-account-cached.php)      | M2M with token caching for long-running workers    |
| [examples/verify-token.php](examples/verify-token.php)                          | Resource-server style: verify Bearer JWT on inbound requests |
| [examples/psr15-middleware.php](examples/psr15-middleware.php)                  | Reusable PSR-15 middleware for any PSR-15 framework |
| [examples/lambda-handler.php](examples/lambda-handler.php)                      | AWS Lambda (Bref) handler with APCu-backed JWKS cache |
| [examples/scope-authorization.php](examples/scope-authorization.php)            | Scope/role-based access control patterns           |
| [examples/smoke.php](examples/smoke.php)                                        | End-to-end smoke against a running auth server     |

---

## Local development against a dev auth server

```bash
# 1. Register a client in /admin/clients with redirect URI http://localhost:9000/callback
#    (or create a service-account client for M2M flows).

# 2. Run an example against your dev auth server
AUTH_ISSUER=http://localhost:8003 \
AUTH_CLIENT_ID=cli_xxx \
AUTH_CLIENT_SECRET=... \
php -S localhost:9000 examples/web-app-callback.php
```

---

## Testing

```bash
composer install
composer test     # PHPUnit (17 tests, 60 assertions)
composer phpstan  # static analysis (level 8)
composer ca       # phpstan + tests
```

Unit tests use no network and no live auth server. To smoke-test the wire
protocol against a running server, run `examples/smoke.php` with valid
credentials in env.

---

## Further reading

- [docs/architecture.md](docs/architecture.md) — package internals, design decisions
- [docs/auth-code-flow.md](docs/auth-code-flow.md) — web app deep dive (PKCE, state, callback)
- [docs/service-account.md](docs/service-account.md) — M2M deep dive (caching, retry, secret rotation)
- [docs/jwt-verification.md](docs/jwt-verification.md) — JWKS, claim semantics, key rotation
- [docs/error-handling.md](docs/error-handling.md) — exception hierarchy, retry strategy
- [docs/security.md](docs/security.md) — PKCE, state, secret storage, token storage
- [CHANGELOG.md](CHANGELOG.md)

For contributors and AI assistants working on this package: [CLAUDE.md](CLAUDE.md).

---

## License

MIT. See [LICENSE](LICENSE).
