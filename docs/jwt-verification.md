# JWT verification

## Calling `verify()`

```php
$claims = $auth->verify($jwt);                                // default audience: this client's clientId
$claims = $auth->verify($jwt, expectedAudiences: ['svc_a']);  // explicit audience
$claims = $auth->verify($jwt, expectedAudiences: null);       // skip audience check
```

The verifier performs, in order:

1. **Parse** — 3 base64url segments, decode JSON.
2. **Algorithm** — `header.alg === "RS256"`. Other algs are refused.
3. **Key lookup** — find the JWK in the cached JWKS by `header.kid`. On
   miss, invalidate cache and refetch once before failing.
4. **Signature** — `openssl_verify` with the JWK's `n`/`e` reconstructed
   into a PEM-encoded RSA public key.
5. **Issuer** — `payload.iss === Configuration::$issuer`.
6. **`token_use`** — present and non-empty (`user` or `service`).
7. **Audience** — when `$expectedAudiences` is non-null, `payload.aud` must
   contain at least one of them.
8. **Temporal claims** — `nbf` ≤ now + leeway, `iat` ≤ now + leeway,
   `exp` > now − leeway.

Failure raises `TokenVerificationException`.

## What `Claims` contains

`Claims::fromPayload($payload)` returns a value object with:

| Property / method               | Source                                                   |
|---------------------------------|----------------------------------------------------------|
| `$claims->subject`              | `sub`                                                    |
| `$claims->issuer`               | `iss`                                                    |
| `$claims->audiences`            | `aud` (string or list)                                   |
| `$claims->audience()`           | first of `audiences`, or `null`                          |
| `$claims->issuedAt`             | `iat` (int)                                              |
| `$claims->expiresAt`            | `exp` (int)                                              |
| `$claims->jti`                  | `jti`                                                    |
| `$claims->tokenUse`             | `token_use`                                              |
| `$claims->isUser()`             | `token_use === 'user'`                                   |
| `$claims->isService()`          | `token_use === 'service'`                                |
| `$claims->email`                | `email` (`null` if not in scope)                         |
| `$claims->emailVerified`        | `email_verified`                                         |
| `$claims->name`                 | `name` (display name, scope `profile`)                   |
| `$claims->givenName`            | `given_name` (scope `profile`)                           |
| `$claims->familyName`           | `family_name` (scope `profile`)                          |
| `$claims->phoneNumber`          | `phone_number` (E.164, scope `phone`)                    |
| `$claims->phoneNumberVerified`  | `phone_number_verified` (scope `phone`)                  |
| `$claims->displayName()`        | `name` → `email` → `client_name` → `subject` (best label)|
| `$claims->scopes`               | `scopes` (list, accepts string or list from server)      |
| `$claims->hasScope($s)`         | `in_array($s, scopes)`                                   |
| `$claims->roles`                | `roles` (list)                                           |
| `$claims->hasRole($r)`          |                                                          |
| `$claims->hasAnyRole(...$r)`    |                                                          |
| `$claims->hasAllRoles(...$r)`   | (returns `false` when called with no arguments)          |
| `$claims->hasProjectRole($p, $r)` | `hasRole("{$p}.{$r}")`                                 |
| `$claims->rolesForProject($p)`  | Roles starting with `"{$p}."`, prefix stripped           |
| `$claims->groups`               | `groups`                                                 |
| `$claims->hasGroup($g)`         |                                                          |
| `$claims->hasAnyGroup(...$g)`   |                                                          |
| `$claims->hasAllGroups(...$g)`  |                                                          |
| `$claims->isAdmin`              | `is_admin === true`                                      |
| `$claims->clientId`             | `client_id` (service token only)                         |
| `$claims->clientName`           | `client_name` (service token only)                       |
| `$claims->isExpired($now=null)` | `($now ?? time()) >= expiresAt`                          |
| `$claims->secondsUntilExpiration($now=null)` | `max(0, expiresAt - ($now ?? time()))`     |
| `$claims->claim($name)`         | Raw claim (escape hatch for non-standard claims)         |
| `$claims->all`                  | Raw decoded payload (escape hatch)                       |

## Authorization guards

Sugar for "require, else 403":

```php
$claims->requireRole('translator.editor');
$claims->requireAnyRole('translator.editor', 'translator.admin');
$claims->requireGroup('vip-users');
$claims->requireScope('email');
$claims->requireUserToken();      // throws if a service token was presented
$claims->requireServiceToken();
```

All raise `AuthorizationException` on failure. Catch it where you'd send
HTTP 403:

```php
try {
    $claims = $auth->verify($jwt);
    $claims->requireUserToken();
    $claims->requireGroup('translate-editor');
} catch (\Stromcom\AuthClient\Exception\TokenVerificationException) {
    http_response_code(401);
    exit;
} catch (\Stromcom\AuthClient\Exception\AuthorizationException) {
    http_response_code(403);
    exit;
}
```

## Scope-driven claim filtering

For **user tokens**, the auth server filters claims by OIDC scope:

| Scope     | Claims emitted in JWT                                                            |
|-----------|----------------------------------------------------------------------------------|
| `openid`  | `sub`                                                                            |
| `profile` | `name`, `given_name`, `family_name`, `picture`, `locale`, `zoneinfo`, `updated_at` |
| `email`   | `email`, `email_verified`                                                        |
| `phone`   | `phone_number`, `phone_number_verified`                                          |
| `roles`   | `roles`, `is_admin`                                                              |
| `groups`  | `groups`                                                                         |

A user token issued with `scope=openid email` contains `sub`, `email`,
`email_verified`, **and nothing else from the user profile**. If you need
`roles` for authorization, request `scope=roles` at `beginAuthorization()`.

For **service tokens**, scope does not filter claims. `client_id`,
`client_name`, `roles`, `is_admin`, `token_use` are always present. `groups`
is never present (groups are a per-user concept).

## Key rotation

The auth server publishes its public key as a JWK at `/.well-known/jwks.json`
with `kid = sha256(public_pem)[:16]`. When the server rotates keys:

1. Server admins generate a new keypair and update SSM.
2. Server lambdas redeploy.
3. New tokens are signed with the new `kid`.
4. JWKS contains the new `kid` (and may keep the old one briefly).
5. SDK consumers see a `kid` miss → invalidate JWKS cache → refetch →
   verification succeeds.

The transparent retry inside `TokenVerifier` handles this without any
caller action.

## JWKS caching

Pick the cache that matches your runtime:

| Backend                 | When to use                                                            |
|-------------------------|------------------------------------------------------------------------|
| `InMemoryJwksCache`     | Per-process. Fine for CLI / cron / one-shot scripts. On long-running workers (RoadRunner, Swoole, Lambda with a static `Client`) it survives across requests within that process. |
| `ApcuJwksCache`         | **AWS Lambda + Bref `php-fpm`** and traditional PHP-FPM. Kernel shared memory, visible to every worker in the container/host. Survives across warm invocations. Best default for any FPM deployment. |
| `FileJwksCache`         | Shared filesystem on a single host (rare nowadays). Falls back gracefully if APCu isn't available. |
| Custom `JwksCacheInterface` impl | Redis / Memcached for multi-instance fleets behind a load balancer.   |

### AWS Lambda (Bref `php-fpm`)

```php
use Stromcom\AuthClient\Jwks\ApcuJwksCache;

$auth = new Client($configuration, jwksCache: new ApcuJwksCache());
```

Bref's `php-84-fpm` layer enables APCu by default. Entries live in kernel
shared memory and are visible to every FPM worker in the same Lambda
container. A cold start does one JWKS fetch (~30 ms); the next ~thousands
of invocations in that container read from APCu (microseconds).

Pattern: build the `Client` once per container by keeping it in a static.
See [`examples/lambda-handler.php`](../examples/lambda-handler.php) for the
full handler skeleton.

### Filesystem fallback

```php
use Stromcom\AuthClient\Jwks\FileJwksCache;

$auth = new Client(
    $configuration,
    jwksCache: new FileJwksCache(sys_get_temp_dir() . '/stromcom-auth-jwks'),
);
```

The directory is created with mode 0700; files are written with mode 0600.

### Custom backend (Redis / Memcached / PSR-16)

For multi-instance deployments behind a load balancer, implement
`JwksCacheInterface` against a shared backend (Redis, Memcached):

```php
use Stromcom\AuthClient\Jwks\JwksCacheInterface;

final class RedisJwksCache implements JwksCacheInterface {

    public function __construct(private readonly \Redis $redis) {}

    public function get(string $key): ?array {
        $raw = $this->redis->get('jwks:' . sha1($key));
        if ($raw === false) {
            return null;
        }
        $decoded = json_decode($raw, true);
        return is_array($decoded) ? $decoded : null;
    }

    public function set(string $key, array $jwks, int $ttlSeconds): void {
        $this->redis->setex('jwks:' . sha1($key), $ttlSeconds, json_encode($jwks));
    }

    public function delete(string $key): void {
        $this->redis->del('jwks:' . sha1($key));
    }
}
```

## Performance

Verification is fast. After the first JWKS fetch (one HTTP round-trip per
hour), each `verify()` call does:

- JSON decode header + payload (2 × small JSON)
- base64url decode signature (~256 bytes)
- ASN.1 reconstruction of an RSA public key (~1 ms first time, cacheable)
- `openssl_verify` (~100 µs)

Total per call: ≈ 1 ms on modern hardware. No allocation pressure to worry
about for typical request rates.

## Why not call `/me` instead

The `userInfo()` method on `Client` works but adds an HTTP round-trip to
every request. It also creates a hard dependency on the auth server being
reachable (vs. cached JWKS). Use `verify()` in production; use `/me` for
debugging or ad-hoc scripts where you don't want to think about JWT parsing.
