# JWT verification

This SDK exposes **two** verification methods because RFC 9068 access tokens
and OIDC Core 1.0 id_tokens are different JWT profiles with different rules.

| Token type        | Method                                     | Spec               |
|-------------------|--------------------------------------------|--------------------|
| Access token      | `Client::verify($jwt, $expectedAudience)`  | RFC 9068 §2        |
| OIDC id_token     | `Client::verifyIdToken($jwt, $nonce)`      | OIDC Core 1.0 §3.1.3.7 |

Never feed an id_token to `verify()` or an access token to `verifyIdToken()` —
the `typ` JOSE header is checked on both paths to prevent cross-type
confusion (RFC 8725 §3.11).

## Calling `verify()` (RFC 9068 access tokens)

```php
$claims = $auth->verify($jwt, $auth->configuration->clientId);
$claims = $auth->verify($jwt, 'svc_resource_server');   // when a resource server has its own audience
```

The verifier enforces, in order:

1. **Parse** — 3 base64url segments, decode JSON.
2. **Algorithm** — `header.alg === "RS256"`. Other algs are refused.
3. **JOSE `typ`** — MUST be `at+jwt` (or `application/at+jwt`); RFC 9068 §2.1.
4. **Key lookup** — find the JWK in the cached JWKS by `header.kid`. On
   miss, invalidate cache and refetch once before failing.
5. **Signature** — `openssl_verify` with the JWK's `n`/`e` reconstructed
   into a PEM-encoded RSA public key.
6. **Issuer** — `payload.iss === Configuration::$issuer`.
7. **Audience** — `payload.aud` MUST contain `$expectedAudience`.
8. **Temporal claims** — `nbf` ≤ now + leeway, `iat` ≤ now + leeway,
   `exp` > now − leeway.
9. **Required claims present** — `sub`, `client_id`, `jti`, `iat` (RFC 9068 §2.2).

Failure raises `TokenVerificationException`.

> **Note on `token_use`.** This is a stromcom-specific extension claim — not
> defined by RFC 9068 — and is *not* enforced by the verifier. It is still
> exposed on `Claims::$tokenUse` (nullable) and used by `Claims::isUser()` /
> `Claims::isService()` / `Claims::requireUserToken()` / `Claims::requireServiceToken()`
> if you need to discriminate.

## Calling `verifyIdToken()` (OIDC Core 1.0 id_tokens)

```php
// In your /callback handler, after exchangeCode():
$claims = $auth->verifyIdToken($tokens->idToken, $nonceFromSession);
// Now invalidate $nonceFromSession — it is one-time use.
unset($_SESSION['oauth_nonce']);
```

The verifier enforces, in order, per OIDC Core 1.0 §3.1.3.7:

1. **Parse** — 3 base64url segments, decode JSON.
2. **Algorithm** — `header.alg === "RS256"`.
3. **JOSE `typ`** — MUST NOT be `at+jwt` (prevents access-token confusion).
4. **Key lookup** — by `header.kid` (with cache-rotation retry).
5. **Signature** — RS256 over JWKS public key.
6. **Issuer** — `payload.iss === Configuration::$issuer`.
7. **Audience** — `payload.aud` MUST contain `Configuration::$clientId`.
8. **`azp`** — when `aud` has multiple entries OR `azp` is present, `azp`
   MUST equal `Configuration::$clientId`.
9. **Temporal claims** — `exp` / `iat` valid w.r.t. clock with leeway.
10. **Nonce** — `payload.nonce` MUST be a non-empty string equal (timing-safe)
    to `$expectedNonce`.
11. **Required claims present** — `sub`, `iat`.

`$expectedNonce` MUST be a non-empty string — pass the nonce returned by
`beginAuthorization()` and persisted in the user's session.

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
| `$claims->tokenUse`             | `token_use` (stromcom extension, nullable — not in RFC 9068) |
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
    $claims = $auth->verify($jwt, $auth->configuration->clientId);
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
`client_name`, `roles`, `is_admin` are always present, and the stromcom-specific
`token_use=service` is also emitted by the auth server. `groups` is never present
(groups are a per-user concept).

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
