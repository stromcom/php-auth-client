# Authorization Code + PKCE — web application integration

This guide walks through integrating the SDK into a web application that
logs users in via auth.stromcom.cz.

> Working example: [`examples/web-app-callback.php`](../examples/web-app-callback.php).

## When to use this flow

- User-facing web applications, single-page apps with a server backend, or
  mobile apps with a backend.
- Any time you need a **human identity** (`token_use=user`).

For machine-to-machine, use Client Credentials instead — see
[service-account.md](service-account.md).

## Prerequisites

1. **Register a client** in the auth server's admin UI (`/admin/clients`),
   or via CLI:

   ```bash
   composer client:create -- \
       --project=auth \
       --name=my-web-app \
       --redirect-uri=https://my-app.stromcom.cz/oauth/callback
   ```

   The server emits `client_id` (e.g. `cli_…`) and `client_secret` **once**.
   Store the secret in your secret manager (SSM Parameter Store, AWS Secrets
   Manager, GitHub Actions secrets, …) — it never appears again.

2. **Whitelist the exact redirect URI** including scheme, host, port and
   path. `https://app/cb` and `https://app/cb/` are different URIs.

3. **Pick scopes** based on what claims you need. See
   [jwt-verification.md](jwt-verification.md) for the scope-to-claim mapping.

## The five steps

### 1. Start the flow

Anywhere a protected page detects an unauthenticated user:

```php
use Stromcom\AuthClient\Client;
use Stromcom\AuthClient\Configuration;

$auth = new Client(new Configuration(
    clientId:     getenv('AUTH_CLIENT_ID'),
    clientSecret: getenv('AUTH_CLIENT_SECRET'),
    redirectUri:  'https://my-app.stromcom.cz/oauth/callback',
));

session_start();
[$url, $pkce, $state] = $auth->beginAuthorization(
    scopes: ['openid', 'profile', 'email', 'groups'],
);

$_SESSION['oauth_verifier'] = $pkce->verifier;
$_SESSION['oauth_state']    = $state;

header('Location: ' . $url);
exit;
```

`beginAuthorization()` returns three values:

- `$url` — the authorization URL with `client_id`, `redirect_uri`, `scope`,
  `state`, `code_challenge`, `code_challenge_method=S256` filled in.
- `$pkce` — a `Pkce` object. **Save `$pkce->verifier`** in the session;
  you'll need it at step 3.
- `$state` — a random 32-char hex string. **Save it** and verify the value
  returned in step 2 matches.

### 2. Receive the callback

The auth server redirects the user back to your `redirectUri` with `code`
and `state` in the query string:

```
https://my-app.stromcom.cz/oauth/callback?code=def50200...&state=abc123...
```

In your `/oauth/callback` handler:

```php
session_start();

$code  = $_GET['code']  ?? null;
$state = $_GET['state'] ?? null;
$saved = $_SESSION['oauth_state'] ?? null;

if (!is_string($code) || !is_string($state) || !is_string($saved)
    || !hash_equals($saved, $state)
) {
    http_response_code(400);
    exit('CSRF check failed.');
}
```

**Use `hash_equals`**, not `==`. Timing-safe comparison defeats timing-based
state inference attacks.

### 3. Exchange the code for tokens

```php
$verifier = $_SESSION['oauth_verifier'] ?? '';
unset($_SESSION['oauth_verifier'], $_SESSION['oauth_state']);

try {
    $tokens = $auth->exchangeCode($code, $verifier);
} catch (\Stromcom\AuthClient\Exception\OAuthServerException $e) {
    http_response_code(401);
    exit('OAuth error: ' . $e->errorCode);
}
```

`$tokens` is a `TokenSet` with:

- `$tokens->accessToken` — the JWT.
- `$tokens->refreshToken` — opaque refresh token (for renewing).
- `$tokens->expiresAt` — Unix timestamp.
- `$tokens->expiresIn` — seconds.
- `$tokens->scope` — granted scopes (may be narrower than requested).

### 4. Persist the tokens

```php
setcookie('access_token', $tokens->accessToken, [
    'expires'  => $tokens->expiresAt,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Lax',
]);

if ($tokens->refreshToken !== null) {
    setcookie('refresh_token', $tokens->refreshToken, [
        'expires'  => time() + 14 * 24 * 3600,
        'path'     => '/',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

header('Location: /');
```

**Cookie attributes you should not skip:**

- `secure: true` — never send over HTTP.
- `httponly: true` — keep JS out of the access token.
- `samesite: Lax` for access token (so navigation links work),
  `samesite: Strict` for refresh token (it should never leak cross-origin).

For SPAs, you can return the token in a response body and store it in
memory — never in `localStorage` (XSS-readable).

### 5. Verify on every request

```php
$jwt = $_COOKIE['access_token'] ?? null;
if (!is_string($jwt)) {
    header('Location: /login');
    exit;
}

try {
    $claims = $auth->verify($jwt);
} catch (\Stromcom\AuthClient\Exception\TokenVerificationException) {
    // Signature failed, or token expired, or token_use mismatch.
    header('Location: /login');
    exit;
}

// Authorize
$claims->requireUserToken();
$claims->requireGroup('translate-editor');

$userId = $claims->subject;
$email  = $claims->email;
```

JWKS is cached for 1 hour by default, so this verification does not hit the
auth server per request.

## Refreshing the access token

The access token expires after 15 minutes (server-configured). When it does,
exchange the refresh token for a new pair:

```php
$refreshToken = $_COOKIE['refresh_token'] ?? null;
if (!is_string($refreshToken)) {
    header('Location: /login');
    exit;
}

try {
    $tokens = $auth->refresh($refreshToken);
} catch (\Stromcom\AuthClient\Exception\OAuthServerException) {
    // Refresh failed — token revoked, expired or family compromised.
    setcookie('refresh_token', '', ['expires' => 1, 'path' => '/']);
    header('Location: /login');
    exit;
}

// IMPORTANT: refresh tokens rotate. The OLD refresh token is now invalid.
// Persist $tokens->refreshToken (the NEW one) immediately.
```

If you forget to persist the new refresh token, the next refresh call will
fail and the user will be logged out — a common bug.

## Logout

```php
// Clear your own cookies first.
setcookie('access_token',  '', ['expires' => 1, 'path' => '/']);
setcookie('refresh_token', '', ['expires' => 1, 'path' => '/']);
session_destroy();

// Then redirect to the auth server to drop the SSO session cookie.
header('Location: ' . $auth->logoutUrl('https://my-app.stromcom.cz/'));
```

Note: the auth server's logout drops its own session cookie. **Tokens you
already issued remain valid until their `exp`**. There is no token
revocation endpoint exposed.

## `prompt=login` — forcing re-authentication

To force the user to re-enter credentials (e.g. for a sensitive operation):

```php
[$url, $pkce, $state] = $auth->beginAuthorization(
    extraParams: ['prompt' => 'login'],
);
```

The auth server will show the login form even if there's an active SSO
session.

## Scope-driven claim filtering

The auth server applies the OIDC Core 1.0 §5.4 scope-to-claim filter. A user
who requests only `scope=openid email` will get a JWT containing `sub` and
`email`, but **not** `name`, `roles`, `groups`. This is intentional — the
client requests what it needs.

| Scope     | Claims emitted                                                                     |
|-----------|------------------------------------------------------------------------------------|
| `openid`  | `sub`                                                                              |
| `profile` | `name`, `given_name`, `family_name`, `picture`, `locale`, `zoneinfo`, `updated_at` |
| `email`   | `email`, `email_verified`                                                          |
| `phone`   | `phone_number`, `phone_number_verified`                                            |
| `roles`   | `roles`, `is_admin`                                                                |
| `groups`  | `groups`                                                                           |

If your authorization logic depends on `groups`, request `scope=groups`
explicitly.

## Common errors

| Symptom                                                       | Cause                                                            |
|---------------------------------------------------------------|------------------------------------------------------------------|
| `OAuthServerException: invalid_grant`                         | Code already used, expired (10 min TTL), or PKCE verifier mismatch |
| `OAuthServerException: invalid_client`                        | Wrong `client_secret` or unknown `client_id`                     |
| `OAuthServerException: invalid_request` at `/oauth/authorize` | `redirect_uri` not whitelisted (must match exactly)              |
| User logged out every few minutes                              | New refresh token from `/oauth/token` response not persisted     |
| `TokenVerificationException: signature failed`                | JWT signed with a key not in the JWKS (rotation lag)             |
| `TokenVerificationException: iss missing/mismatch`            | `issuer` config doesn't match what the server emits              |
| `TokenVerificationException: aud mismatch`                    | Token issued for a different client_id                           |
