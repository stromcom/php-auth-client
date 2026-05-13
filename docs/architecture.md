# Architecture

This document describes how the SDK is laid out internally and the decisions
behind that layout. For high-level usage, see [README.md](../README.md).

## Layered structure

```
src/
├── Client.php          ← public facade (the only thing most consumers touch)
├── Configuration.php   ← immutable config + endpoint derivation
├── TokenSet.php        ← /oauth/token response value object
├── Claims.php          ← decoded JWT payload value object
├── Pkce.php            ← PKCE verifier + challenge helper
├── TokenVerifier.php   ← JWKS lookup + lcobucci/jwt validation
├── Http/
│   ├── HttpClientInterface.php
│   ├── CurlHttpClient.php
│   └── RawResponse.php
├── Jwks/
│   ├── JwksCacheInterface.php
│   ├── InMemoryJwksCache.php
│   └── FileJwksCache.php
├── Internal/                   ← @internal, do not import from outside
│   ├── JwkRsaKey.php           ← JWK (n, e) → PEM via ASN.1
│   └── SystemClock.php         ← PSR-20 clock for lcobucci's temporal constraints
└── Exception/
    ├── AuthClientException.php
    ├── ConfigurationException.php
    ├── TransportException.php
    ├── OAuthServerException.php
    ├── TokenVerificationException.php
    └── AuthorizationException.php
```

`Internal/` is plumbing — JWK→PEM conversion and a tiny PSR-20 clock
implementation that lcobucci's `LooseValidAt` constraint requires. Nothing
under `Internal/` is part of the SDK's public API.

## Request flow — Authorization Code

```
User-Agent      Your app                SDK                       auth.stromcom.cz
    │              │                     │                                │
    │              │ beginAuthorization()│                                │
    │              ├────────────────────►│  Pkce::generate()              │
    │              │◄────────────[url, pkce, state]                       │
    │ ◄── 302 ─────│                     │                                │
    │ /authorize ──┼─────────────────────┼───────────────────────────────►│
    │              │                     │                       login + consent
    │ ◄── 302 ─────┼─────────────────────┼────────────────[code, state]   │
    │              │ exchangeCode(code, verifier)                         │
    │              ├────────────────────►│  POST /oauth/token             │
    │              │                     ├───────────────────────────────►│
    │              │                     │◄──────────────── TokenSet      │
    │              │◄──── TokenSet ──────┤                                │
    │              │                     │                                │
    │   ── /api ──►│ verify(jwt)         │                                │
    │              ├────────────────────►│  GET /.well-known/jwks.json    │
    │              │                     ├──────────── (once / hour) ────►│
    │              │                     │◄───────────────── JWKS         │
    │              │                     │  openssl_verify(...)           │
    │              │◄────── Claims ──────┤                                │
```

The SDK never holds session or token state. The caller persists `verifier`
and `state` between the two calls (typically PHP `$_SESSION`). The caller
persists `TokenSet` after exchange (typically cookies or DB).

## Request flow — Client Credentials

```
Your worker                    SDK                       auth.stromcom.cz
    │                           │                                │
    │ clientCredentials()       │                                │
    ├──────────────────────────►│  POST /oauth/token             │
    │                           ├───────────────────────────────►│
    │                           │◄────────────── TokenSet        │
    │◄──── TokenSet ────────────┤                                │
    │                           │                                │
    │ Authorization: Bearer …                                    │
    ├────────────────────────────────────────────────────────────► (your downstream API)
```

For workers that issue many calls, cache the `TokenSet` until
`isExpired(time(), leeway: 60)`. See
[`examples/service-account-cached.php`](../examples/service-account-cached.php).

## Why `lcobucci/jwt`

JWT parsing, signature verification and temporal-claim validation
(`exp`/`nbf`/`iat` with leeway) are delegated to
[`lcobucci/jwt`](https://github.com/lcobucci/jwt). Reasoning:

1. **Same library as the auth server.** `auth.stromcom.cz` uses
   `lcobucci/jwt` transitively via `league/oauth2-server`. Sharing the JWT
   layer means both sides interpret edge cases (float `iat`, claim type
   coercion, encoding quirks) identically.
2. **Audit clean.** As of the 1.0 release, `composer audit` reports no
   advisories against `lcobucci/jwt: ^5.5`. (We initially shipped a
   hand-rolled verifier because `firebase/php-jwt` was — and still is —
   flagged by `composer audit`; `lcobucci/jwt` doesn't have that problem.)
3. **Battle-tested constraints.** `LooseValidAt`, `SignedWith`, `IssuedBy`,
   `PermittedFor` are well-known, audited primitives. We compose them.

What we still own:

- **JWKS fetching, caching and key-rotation orchestration** (`Jwks/`, the
  `findJwk` + retry-on-miss loop in `TokenVerifier`). `lcobucci/jwt` knows
  about PEM keys, not JWKS endpoints.
- **JWK→PEM bridge** in
  [`src/Internal/JwkRsaKey.php`](../src/Internal/JwkRsaKey.php). It
  constructs a PEM-encoded RSA public key from JWK `n` and `e` by emitting
  standard ASN.1 DER (SubjectPublicKeyInfo) — ~70 LoC.
- **`token_use` strict check.** Not a standard claim, lcobucci doesn't know
  about it. Asserted in `TokenVerifier::verify()` after the standard
  constraints pass.
- **Minimal PSR-20 clock** (`Internal/SystemClock`). Avoids pulling
  `lcobucci/clock` as another transitive dep.

## Why no PSR-7 / PSR-17 / PSR-18

PSR-7 messages plus a PSR-18 client would force every consumer to bring an
HTTP factory and discovery wiring. Most consumers want "give me tokens, give
me claims" — not a chain of HTTP middleware. The `HttpClientInterface` is one
method wide and takes/returns plain types; an adapter to Guzzle or Symfony
HttpClient is a dozen lines.

## Why no PSR-3 logger

Same logic as PSR-18 — adding `psr/log` as a hard dependency makes the SDK
worse for the 90 % of consumers who don't want logging. If a need arises,
add an **optional** `?LoggerInterface` argument to `Client` that defaults to
`null` (no logging).

## Strict-mode semantics

`TokenVerifier` enforces:

| Check               | Behavior on failure                              |
|---------------------|--------------------------------------------------|
| 3-segment JWT       | `TokenVerificationException`                     |
| `alg = RS256`       | `TokenVerificationException` (we don't accept other algs) |
| `kid` present, found in JWKS | Invalidate cache once, re-fetch, retry; then `TokenVerificationException` |
| RS256 signature     | `TokenVerificationException`                     |
| `iss` matches configured issuer | `TokenVerificationException`            |
| `token_use` non-empty string    | `TokenVerificationException`            |
| `exp` not yet reached (with `leeway`) | `TokenVerificationException`      |
| `nbf` reached (with `leeway`)   | `TokenVerificationException`            |
| `iat` not in the future (with `leeway`) | `TokenVerificationException`    |
| `aud` matches expected (when `$expectedAudiences` passed) | `TokenVerificationException` |

`Client::verify()` passes `$expectedAudiences = [$clientId]` by default — a
JWT must have the consuming app's own `client_id` in its `aud` claim.

## JWKS caching strategy

The verifier:

1. Asks the cache for `$jwksUri` → if a hit, uses it.
2. On `kid` miss (key rotated), deletes the cache entry and re-fetches once.
3. On the second miss, throws `TokenVerificationException`.

This handles key rotation transparently within one request, without
restarting the process or polling.

The cache TTL defaults to `Configuration::DEFAULT_JWKS_TTL` (1 hour) and
matches the `Cache-Control: max-age=3600` the auth server publishes.

`FileJwksCache` is appropriate for typical web apps where each request is a
separate PHP process. `InMemoryJwksCache` is appropriate for long-running
workers (PHP-FPM with opcache hot, RoadRunner, Swoole, etc.). For
multi-instance deployments behind a load balancer, plug a shared backend
(Redis, Memcached) by implementing `JwksCacheInterface` directly.

## Coupling to auth.stromcom.cz

The SDK is paired specifically with `auth.stromcom.cz`. The SDK relies on:

- RS256 only (no HS256, no ES256).
- `kid` always present in the JWT header and in the JWKS.
- `iss` always present (RFC 9068 strict).
- `token_use` always present (one of `user`, `service`).
- Service tokens have `sub == client_id == aud`.
- The OIDC scope-to-claim mapping (filter on the server, not the client).

If the server changes any of this, the SDK needs corresponding updates and
test coverage.
