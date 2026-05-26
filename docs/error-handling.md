# Error handling

All exceptions thrown by the SDK extend `AuthClientException`. Catching that
base type guarantees you handle every failure mode.

## Hierarchy

```
\RuntimeException
└─ Stromcom\AuthClient\Exception\AuthClientException
   ├─ ConfigurationException        – static config error, fix the code/env
   ├─ TransportException            – network failure, retry may help
   ├─ OAuthServerException          – server returned an `error` payload
   ├─ TokenVerificationException    – JWT failed signature/claims check
   └─ AuthorizationException        – role/group/scope/token_use missing
```

## When each one happens

### `ConfigurationException`

Static problem — you passed bad values to `Configuration` or `Client`.

| Trigger                                     | Fix                                       |
|---------------------------------------------|-------------------------------------------|
| `clientId === ''`                           | Set `AUTH_CLIENT_ID` env / fix code       |
| `timeout < 1`                               | Use a positive integer                    |
| `issuer` doesn't start with `http://` or `https://` | Use an absolute URL              |
| `redirectUri` required but missing          | Set it before `beginAuthorization()` / `exchangeCode()` |
| `clientSecret` required but missing         | Set it before `clientCredentials()`       |
| `FileJwksCache` directory not writable      | Pick a writable dir or use `InMemoryJwksCache` |

**Retry strategy:** none. Fix the config.

### `TransportException`

Network-level failure (cURL error, timeout, DNS, TLS, …) when calling the
auth server.

```php
catch (TransportException $e) {
    // $e->getMessage() includes the cURL error code + message
}
```

**Retry strategy:** safe to retry with backoff for transient errors. The
auth server's calls are idempotent for `GET /jwks`, `GET /me`,
`GET /openid-configuration`. `POST /oauth/token` for `client_credentials` is
also effectively idempotent — at worst you waste a token. **Don't blindly
retry `authorization_code` or `refresh_token` grants** — codes and refresh
tokens are single-use and you'll get `invalid_grant` on the second attempt.

### `OAuthServerException`

The auth server replied with `4xx` and an `error` field. Inspect:

```php
catch (OAuthServerException $e) {
    $e->statusCode;        // HTTP status, e.g. 400
    $e->errorCode;         // OAuth error code, e.g. "invalid_grant"
    $e->errorDescription;  // optional human-readable detail
    $e->errorUri;          // optional spec link
    $e->raw;               // full decoded body
}
```

Common `errorCode` values you'll see on `/oauth/token`:

| `errorCode`            | Meaning                                                       | Retry?                                 |
|------------------------|---------------------------------------------------------------|----------------------------------------|
| `invalid_client`       | Wrong `client_id`/`client_secret`, or client revoked          | No — fix credentials                   |
| `invalid_grant`        | Code/refresh token used, expired, revoked, or PKCE mismatch   | No — restart the flow                  |
| `invalid_request`      | Malformed request (missing param, bad redirect_uri match)     | No — fix the request                   |
| `invalid_scope`        | Requested scope not allowed for this client                   | No — remove the bad scope              |
| `unauthorized_client`  | Grant type not enabled for this client                        | No — admin must enable it              |
| `unsupported_grant_type` | Grant type unknown to the server                            | No — bug                               |
| `server_error`         | Server crashed                                                | Yes, with backoff                      |
| `temporarily_unavailable` | Server is shedding load                                    | Yes, with backoff                      |

The server may also wrap errors in the project's unified shape
`{"error": {"code": "...", "message": "..."}}`. The SDK normalizes both
shapes into `OAuthServerException`.

### `TokenVerificationException`

JWT failed one of the checks in `TokenVerifier`. The message identifies
which check failed:

| Message                                       | Cause                                                                          |
|-----------------------------------------------|--------------------------------------------------------------------------------|
| `Malformed JWT: expected 3 segments.`         | Garbage in, not a JWT                                                          |
| `Malformed JWT JSON segment.`                 | Header or payload isn't JSON                                                   |
| `Unsupported JWT alg "..."`                   | Token signed with non-RS256 alg (we refuse `none`, `HS256`, etc.)              |
| `No matching JWK found for kid "..."`         | Token signed with a `kid` not in JWKS — usually means the auth server rotated keys after this token was minted, or the token is forged |
| `JWT signature verification failed.`          | Bad signature                                                                  |
| `JWT is missing iss claim (RFC 9068 REQUIRED).` | Server didn't emit `iss` — likely an old server version                      |
| `JWT issuer mismatch: expected "...", got "...".` | `Configuration::$issuer` doesn't match what the server emits               |
| `JWT is missing JOSE "typ" header — RFC 9068 access tokens MUST set typ=at+jwt.` | Server emitted a JWT without a `typ` header (non-RFC 9068)        |
| `Unexpected JWT typ "..." — RFC 9068 access tokens MUST set typ=at+jwt. For OIDC id_tokens use verifyIdToken() instead.` | id_token fed into `verify()` instead of `verifyIdToken()`         |
| `Refusing to verify a token with typ=at+jwt as an OIDC id_token (token confusion).` | Access token fed into `verifyIdToken()`                          |
| `JWT is missing required string claim "..." `   | RFC 9068 §2.2 REQUIRED claim absent (`sub`, `client_id`, `jti`)                |
| `JWT is missing required integer claim "..."` | RFC 9068 §2.2 REQUIRED `iat` absent or not an integer                          |
| `OIDC id_token is missing the \`nonce\` claim.` | Server didn't echo back the nonce, or you called `verifyIdToken` with a non-OIDC token |
| `OIDC id_token \`nonce\` does not match the expected value.` | Replay attempt, or nonce reused across flows                        |
| `OIDC id_token \`azp\` ... does not match this client_id.` | Multi-audience id_token issued for a different relying party             |
| `JWT audience mismatch: expected [...], got [...].` | Token issued for a different client                                      |
| `JWT is expired.`                             | `now > exp` (even after `leeway`)                                              |
| `JWT is not yet valid (nbf).`                 | `nbf > now` (clock skew or replay)                                             |
| `JWT iat claim is in the future.`             | Clock skew between server and consumer                                         |

**Retry strategy:** never silently. Map to HTTP 401 and force re-authentication.

The exception type does NOT distinguish "expired" from "invalid signature"
on purpose — both are equally untrusted, and the response to the user is
the same (start the auth flow again).

### `AuthorizationException`

The token verified fine, but lacks the required role/group/scope/token_use.
Map to HTTP 403:

```php
try {
    $claims->requireRole('translator.editor');
} catch (AuthorizationException $e) {
    http_response_code(403);
    exit($e->getMessage());
}
```

Factory methods on the exception class capture which assertion failed
(`missingRole`, `missingGroup`, `missingScope`, `wrongTokenUse`). For audit
logging:

```php
catch (AuthorizationException $e) {
    $auditLog->forbidden($claims->subject, $e->getMessage());
    http_response_code(403);
}
```

## Recommended response mapping

```php
use Stromcom\AuthClient\Exception\AuthClientException;
use Stromcom\AuthClient\Exception\AuthorizationException;
use Stromcom\AuthClient\Exception\OAuthServerException;
use Stromcom\AuthClient\Exception\TokenVerificationException;
use Stromcom\AuthClient\Exception\TransportException;

try {
    // ...
} catch (TokenVerificationException $e) {
    return new Response(401, ['WWW-Authenticate' => 'Bearer error="invalid_token"']);
} catch (AuthorizationException $e) {
    return new Response(403, body: $e->getMessage());
} catch (OAuthServerException $e) {
    return new Response(502, body: 'Auth server error: ' . $e->errorCode);
} catch (TransportException $e) {
    return new Response(504, body: 'Auth server unreachable');
} catch (AuthClientException $e) {
    return new Response(500, body: 'Auth integration error');
}
```

## Logging

The SDK doesn't log. When you catch an SDK exception, log it with enough
context to debug:

```php
$logger->warning('jwt verification failed', [
    'exception' => $e::class,
    'message'   => $e->getMessage(),
    'client_id' => $auth->configuration->clientId,
    'issuer'    => $auth->configuration->issuer,
    'jwt_kid'   => /* parse header.kid yourself if needed */,
]);
```

Avoid logging the JWT itself, the refresh token, or the client secret. Log
`jti` if you need to correlate audit trails on the auth server side.
