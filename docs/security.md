# Security

This document collects security guidance specific to integrating
`stromcom/auth-client` into a web application or backend service.

## PKCE

The SDK uses RFC 7636 PKCE with `code_challenge_method=S256` by default. The
`code_verifier` is 32 bytes of `random_bytes` base64url-encoded (43 chars,
matching the RFC's 43–128 character range with the highest entropy that
keeps a single AES block).

**You don't have to think about this** — `beginAuthorization()` generates a
fresh PKCE pair on every call and returns the verifier so you can store it.
Don't reuse verifiers across flows.

## State parameter (CSRF)

`beginAuthorization()` returns a 32-character hex `state`. Store it in your
session and compare with the value the auth server echoes back in the
callback **with `hash_equals`** (timing-safe).

```php
if (!hash_equals($_SESSION['oauth_state'] ?? '', $_GET['state'] ?? '')) {
    exit('CSRF');
}
```

Don't use `==` or `===` — both leak comparison timing.

## Storing the client secret

The client secret is functionally a password. Treat it accordingly:

- Read from a secret manager (SSM Parameter Store, AWS Secrets Manager,
  Vault, GitHub Actions secrets, …).
- Never commit it to git.
- Never log it.
- Never send it to the browser.
- Never expose it in error responses.

Public clients (SPAs without a backend, mobile apps without a backend)
should not use a client secret at all — they use PKCE alone. The auth
server supports public clients via the `--public` flag at client creation.

## Storing tokens (web apps)

The access token is short-lived (default 15 min) and **bearer** — anyone
with it impersonates the user. Storage rules:

| Storage location               | Verdict                                    |
|--------------------------------|--------------------------------------------|
| `HttpOnly; Secure; SameSite=Lax` cookie | ✅ Recommended for web apps         |
| In-memory (SPA, never persisted)        | ✅ Recommended for SPAs              |
| `localStorage` / `sessionStorage`       | ❌ Readable by XSS                  |
| Plain (non-`HttpOnly`) cookie           | ❌ Readable by XSS                  |
| URL query string                        | ❌ Logged everywhere               |

The refresh token (longer-lived, default 14 days) is even more sensitive:

| Storage location                                            | Verdict             |
|-------------------------------------------------------------|---------------------|
| `HttpOnly; Secure; SameSite=Strict; Path=/oauth/refresh` cookie | ✅ Recommended  |
| Encrypted at rest in a server-side DB keyed by session ID   | ✅ For SPAs         |
| Anywhere readable by JS                                     | ❌ Catastrophic     |

The auth server **rotates** refresh tokens — every successful refresh
returns a new refresh token and invalidates the old one. If a refresh token
leaks and is used by the attacker before the user's next refresh, the
user's next refresh will fail (the server detects token-family compromise)
and force a re-login.

## Storing tokens (service accounts)

Service tokens have no refresh component — they live for 1 hour and are
re-issued on demand. Keep them in memory only. Don't write them to disk.

If you cache them (see
[`examples/service-account-cached.php`](../examples/service-account-cached.php)),
either:

- Keep them in process memory (in-memory cache, APCu, …).
- Or use an encrypted backend (e.g. Redis with TLS to a private VPC).

Never persist plain service tokens to a shared filesystem.

## Redirect URI handling

The auth server enforces exact-match on `redirect_uri`. Implications:

- `https://app.example.com/cb` and `https://app.example.com/cb/` (trailing
  slash) are different URIs and must be whitelisted separately if you need
  both.
- The query string is not part of the comparison and **must not be used**
  to encode state — use the `state` parameter.
- `http://localhost:*` works for local dev; production must be `https://`.

## Logout semantics

`Client::logoutUrl()` builds a URL that drops the **auth server's** SSO
session cookie. It does **not** revoke access tokens or refresh tokens.
After logout:

- The user's next call to `/oauth/authorize` will re-prompt for credentials.
- Tokens you've already issued remain valid until their `exp`.

If you need immediate revocation:

1. Clear your own access_token and refresh_token cookies.
2. Optionally maintain a small in-process blocklist of `jti` values
   from explicitly logged-out tokens, checked in your `verify()` wrapper.

There is intentionally no token revocation endpoint exposed by the auth
server — JWT bearer model assumes tokens are short-lived.

## JWKS handling

The SDK fetches JWKS over HTTPS to the auth server's issuer URL. Trust
anchor is the system's CA store via cURL.

**Don't disable TLS verification** on `CurlHttpClient`. If you need to
override it for development against a self-signed cert, write a tiny
adapter to `HttpClientInterface` that does so — don't add a config flag
that could ship to production.

## Algorithm pinning

The SDK accepts **only RS256**. Any other `alg` in the JWT header is
refused. This includes:

- `none` — the classic "no algorithm" attack.
- `HS256` / `HS384` / `HS512` — symmetric algorithms that could let an
  attacker who knows the public key forge tokens.
- `ES256` and friends — not used by the server.

This is intentional and should not be relaxed.

## Clock skew

The verifier accepts ±30 seconds of skew by default (`Configuration::$leeway`).
For very large fleets with potentially poor NTP discipline, you may set this
up to ~120 seconds. Anything higher than that should prompt you to fix NTP
instead.

## Token introspection in logs

When logging auth-related events, log only:

- `claims.subject` (the user/client ID — already public per the JWT)
- `claims.jti` (the token's unique identifier, useful for audit correlation)
- `exception class` and `message`

Never log:

- The JWT itself
- The refresh token
- The client secret
- Tokens received from downstream APIs

## Reporting issues

Security issues should go directly to `security@stromcom.cz` (or the
project's GitHub Security tab — never a public issue).
