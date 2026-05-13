# CLAUDE.md — guidance for Claude Code in this repository

You are working on **`stromcom/auth-client`** — the official PHP client SDK
for the `auth.stromcom.cz` SSO/OAuth 2.0 server. This file collects everything
you need to keep this package consistent across future sessions.

## What this package is

Self-contained PHP 8.3+ client library:
- OAuth 2.0 Authorization Code + PKCE flow (web app login)
- OAuth 2.0 Client Credentials flow (machine-to-machine)
- Refresh token grant
- Local JWT verification via JWKS with TTL cache and `kid`-rotation
- UserInfo (`/me`) call
- Logout URL builder
- OIDC discovery (`/.well-known/openid-configuration`)
- RFC 9068 strict (`iss`, `token_use`, `at+jwt` required)

**Production runtime dependencies:** only `lcobucci/jwt: ^5.5` (and its
transitive `psr/clock`). JWT parsing, signature verification and temporal
claim validation go through `lcobucci/jwt`. JWKS fetching, caching, key
rotation, OAuth grant flows and PKCE are in-house. cURL is the HTTP
transport.

## Relationship to other repos

| Repo                                            | Purpose                                              |
|-------------------------------------------------|------------------------------------------------------|
| `../auth.stromcom.cz/`                          | The auth server this SDK talks to. Source of truth for endpoints + JWT claim contract. |
| `../php-customer-sdk/`                          | Sibling SDK with the same code style — mimic it.      |

When adding a feature here, check whether the server (`../auth.stromcom.cz`)
already supports it. The server's `.claude/oauth-flows.md` is the canonical
description of what JWTs contain and what endpoints exist. Don't invent
endpoints — if the SDK needs a new server feature, change the server first.

## Code style

Follow the **exact same style** as `../php-customer-sdk/`:
- PHP 8.3+, `declare(strict_types=1);`
- 2-space indent (the rest of the project ecosystem uses 4 spaces — this SDK
  family uses 2 because the customer SDK established that)
- `final class Foo {` with same-line brace
- Constructor property promotion with `public readonly` everywhere possible
- camelCase method/property names
- No PHPDoc unless adding type information beyond what PHP can express
  (array shapes, `@throws` on interfaces, examples on `Client` methods)
- **No comments unless the WHY is non-obvious.** Code shouldn't explain what
  it does — names should. Comment only the surprising bits: a workaround for
  a third-party bug, a non-obvious invariant, a security-critical decision.

If you ever need an example of what good prose looks like, read the existing
comments in `src/TokenVerifier.php` and `src/Internal/JwkRsaKey.php`. The
comment in `LeagueAccessTokenEntity.php` on the server is also a good model.

## Layered structure

```
src/
├── Client.php                 # Main facade. Per-flow methods.
├── Configuration.php          # Immutable config + endpoint derivation.
├── TokenSet.php               # The /oauth/token response, parsed.
├── Claims.php                 # The decoded JWT payload, with helpers.
├── Pkce.php                   # PKCE verifier + challenge generator.
├── TokenVerifier.php          # JWKS-based RS256 verification.
├── Http/
│   ├── HttpClientInterface.php  # Tiny PSR-7-ish interface (no PSR-7 dep).
│   ├── CurlHttpClient.php       # Default cURL transport.
│   └── RawResponse.php
├── Jwks/
│   ├── JwksCacheInterface.php   # Cache contract.
│   ├── InMemoryJwksCache.php    # Per-process. Good for CLI / workers.
│   ├── ApcuJwksCache.php        # Shared memory. Right default for Lambda + FPM.
│   └── FileJwksCache.php        # Single-host fallback when APCu is unavailable.
├── Internal/
│   ├── JwkRsaKey.php            # JWK (n, e) → PEM via ASN.1.
│   └── SystemClock.php          # PSR-20 clock for lcobucci's LooseValidAt constraint.
└── Exception/
    ├── AuthClientException.php  # Base (catch-all).
    ├── ConfigurationException.php
    ├── TransportException.php
    ├── OAuthServerException.php  # Server returned an OAuth `error` payload.
    ├── TokenVerificationException.php
    └── AuthorizationException.php  # Role/group/scope/token_use guard.
```

**`Internal/` is for plumbing.** Anything under it is `@internal` and not part
of the SDK's public API. Don't expose new helpers there to consumers — if a
helper deserves to be public, move it up.

## Architectural rules

1. **Runtime dependencies are deliberately tiny.** Only `lcobucci/jwt` (and
   its transitive `psr/clock`). If you want to add another, justify it
   against the cost of every consumer pulling it in. Dev-dependencies
   (PHPUnit, PHPStan, php-cs-fixer) are unconstrained.
2. **Don't replace `lcobucci/jwt`.** The auth server uses it transitively
   through `league/oauth2-server`, so both ends share the same JWT
   interpretation. Switching to `firebase/php-jwt` is a downgrade — it's
   currently flagged by `composer audit`. Switching to `web-token/jwt-framework`
   drags in a much larger dependency surface for the same job.
3. **`Client` is the only public facade.** Don't add competing entry points.
   New flows are new methods on `Client`.
4. **HTTP transport is injectable.** All HTTP goes through
   `HttpClientInterface`. Never call cURL directly anywhere else.
5. **JWKS cache is injectable.** Always go through `JwksCacheInterface`.
6. **Strict by default.** RFC 9068 requires `iss`, `token_use`. Don't add a
   "lenient mode" toggle without a strong reason — strict-in-what-you-accept
   is the security default and the server emits those claims.
7. **`Claims` is read-only and rich.** When users ask "how do I check X",
   the answer should be "Claims has a method for that". Add to the API rather
   than telling users to dig into `$claims->all`.
8. **Tests are unit + offline.** Never hit the network from unit tests. For
   end-to-end checks, `examples/smoke.php` exists and is run manually.

## Adding features

### A new grant type
- Add a method on `Client` (mirror `clientCredentials()` / `exchangeCode()`).
- Reuse `postToken()` — don't duplicate the request building.
- Update `docs/auth-code-flow.md` or `docs/service-account.md` (or add a new doc).
- Add a unit test against `Client` with a mock `HttpClientInterface`.

### A new claim from the server
- If it's an OIDC-standard claim → map it explicitly in `Claims::fromPayload`.
- If it's a stromcom-specific claim → same, plus add convenience methods
  (`has*`, `require*`, `*ForProject`, etc.).
- Update the "Claims — object API" section of `README.md`.

### A new exception case
- Always extend `AuthClientException` (so a top-level `catch` works).
- Don't introduce a new exception that doesn't have at least one named
  factory method or constructor parameter capturing the failure context.

## Server-side coupling

This SDK is paired with `auth.stromcom.cz`. **Specific contract relied on:**

- `GET /.well-known/jwks.json` — JWKS, RS256, `kid` from first 16 hex chars
  of `sha256(public_pem)`.
- `GET /.well-known/openid-configuration` — OIDC discovery.
- `POST /oauth/token` — grants: `authorization_code`, `refresh_token`,
  `client_credentials`.
- `GET /oauth/authorize` — PKCE S256 supported.
- `GET /me` — UserInfo with `Authorization: Bearer …`.
- `GET /oauth/logout` — end-session, optional `post_logout_redirect_uri`.

**JWT contract** (see `../auth.stromcom.cz/.claude/oauth-flows.md`):
- Header: `{typ: "at+jwt", alg: "RS256", kid: "..."}`
- Always present: `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`, `scopes`, `token_use`
- Service tokens add: `client_id`, `client_name`, `roles`, `is_admin`
- User tokens add (filtered by scope, OIDC Core 1.0 §5.4):
  `name`, `email`, `email_verified`, `picture`, `locale`, `zoneinfo`,
  `updated_at`, `roles`, `groups`, `is_admin`

If the server changes any of this, this SDK needs corresponding updates.

## Testing

```bash
composer install
composer test       # PHPUnit, no network
composer phpstan    # static analysis, level 8
composer ca         # phpstan + test
```

Unit tests live in `tests/` and mirror the `src/` layout. Use offline
fixtures — JWKS sample documents, baked test keypairs (Windows PHP doesn't
have `openssl.cnf` for runtime keygen). Look at how the server-side
`LeagueAccessTokenEntityTest` solves this for the same reason.

The smoke example (`examples/smoke.php`) is **the** end-to-end test. Run it
manually after non-trivial changes:

```bash
# In ../auth.stromcom.cz: composer serve
# Then create a service account: composer client:create -- --project=auth --name=auth-client-smoke --service-account
AUTH_ISSUER=http://localhost:8003 AUTH_CLIENT_ID=svc_… AUTH_CLIENT_SECRET=… \
  php examples/smoke.php
```

## Documentation

- `README.md` — entry point, quickstart, claim API reference.
- `docs/architecture.md` — internals.
- `docs/auth-code-flow.md` — web app integration deep dive.
- `docs/service-account.md` — M2M deep dive.
- `docs/jwt-verification.md` — JWKS, claims, key rotation.
- `docs/error-handling.md` — exception hierarchy + retry strategies.
- `docs/security.md` — PKCE, state, secret storage, token storage.
- `CHANGELOG.md` — semantic-versioned changelog.
- `examples/*.php` — runnable examples, each self-contained.

**Keep these in sync.** If you change a public API:
1. Update the relevant `docs/*.md`.
2. Update `README.md` if it appears in the quickstart or reference table.
3. Add a `CHANGELOG.md` entry.
4. Add or update an example demonstrating the change.

## What this package is NOT

- Not a generic OAuth 2.0 / OIDC library. It targets exactly one server
  (`auth.stromcom.cz`). Don't generalize without a clear reason.
- Not an RFC 9068 reference. We aim for compliance with what auth.stromcom.cz
  emits; we don't aim to validate every weird edge case some other server
  might produce.
- Not a session manager. Users persist tokens themselves (cookies, DB,
  whatever). The SDK only fetches and verifies.
- Not a "framework". No autowiring, no DI container integration, no service
  provider, no PSR-7 emitter. Plain objects.

## Common questions

**"Should I add Guzzle support?"** No. The `HttpClientInterface` is one
method wide. If a user wants Guzzle, they write an 8-line adapter. Adding a
Guzzle dependency means every consumer of this SDK pulls in Guzzle.

**"Should I add PSR-3 logging?"** Not yet. If you ever do, accept a
`?LoggerInterface` on `Client` and log nothing by default. Don't take a hard
dep on `psr/log`.

**"Should I cache tokens automatically?"** No — token storage is the
caller's concern (they know where their session lives). Provide a recipe in
`examples/service-account-cached.php` instead.

**"User asks for a feature the server doesn't support."** Fix the server
first. This SDK should never paper over a missing server feature with a
client-side workaround (the one exception: defensive parsing of optional
fields). If you're tempted, stop and explain.

## When in doubt

Read the existing code. It's small (~1200 lines), idiomatic, and the
conventions are consistent. New code that breaks the conventions is the
problem, not the conventions.
