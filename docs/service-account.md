# Service account — machine-to-machine

This guide covers the OAuth 2.0 Client Credentials flow: a backend service
authenticates **as itself** (no end user) to call another backend service.

> Working examples:
> - [`examples/service-token.php`](../examples/service-token.php) (one-shot)
> - [`examples/service-account-cached.php`](../examples/service-account-cached.php) (with token caching)

## When to use this flow

- Backend → backend API calls.
- Scheduled jobs / cron / Lambda triggers.
- CI/CD pipelines that need to call internal APIs.
- Anything where the **identity is a service**, not a human.

For user-facing logins, use [Authorization Code](auth-code-flow.md) instead.

## Prerequisites

Register a service account in the admin UI or via CLI:

```bash
composer client:create -- \
    --project=deploy \
    --name=ci-bot \
    --service-account \
    --role=deploy.admin \
    --role=deploy.viewer
```

The server emits `client_id` (starts with `svc_…`) and `client_secret` once.
Store the secret in your secret manager — never in source control.

The `--role` flags pre-assign roles that will appear in the JWT's `roles`
claim. Service accounts don't have groups (groups are per-user).

## Basic usage

```php
use Stromcom\AuthClient\Client;
use Stromcom\AuthClient\Configuration;

$auth = new Client(new Configuration(
    clientId:     'svc_xxxxxxxxxxxxxxxx',
    clientSecret: getenv('AUTH_CLIENT_SECRET'),
));

$tokens = $auth->clientCredentials();

$response = $httpClient->get('https://api.stromcom.cz/v1/deployments', [
    'headers' => ['Authorization' => $tokens->authorizationHeader()],
]);
```

`clientCredentials()` returns a `TokenSet`:

- `$tokens->accessToken` — JWT, valid for 1 hour by default.
- `$tokens->refreshToken` — `null`. Service accounts don't get refresh
  tokens; just request a new access token when needed.
- `$tokens->expiresAt`, `$tokens->expiresIn` — TTL info.

## Token caching for long-running processes

A worker that runs for hours and calls a downstream API on every iteration
shouldn't refetch a token every time. Cache it:

```php
class ServiceTokenCache {

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
```

`isExpired($now, 60)` returns `true` when the token has less than 60 seconds
of life left, so you refresh proactively before downstream calls start
failing with `401`.

For multi-process deployments (PHP-FPM, Lambda concurrency), use a shared
cache backend instead (Redis, APCu, …). See
[`examples/service-account-cached.php`](../examples/service-account-cached.php)
for a working pattern.

## Requesting specific scopes

A client may request a subset of its allowed scopes:

```php
$tokens = $auth->clientCredentials(scopes: ['deploy.write']);
```

The returned scopes (in `$tokens->scope` and the JWT `scopes` claim) are the
**intersection** of what you requested and what the client is allowed.
Requesting an unknown scope returns an error from the server.

> **Note:** roles and groups in the JWT are **not** filtered by scope for
> service tokens. `roles` and `is_admin` are always present (taken from the
> client record in the DB). `groups` are never present for service tokens.
> See [jwt-verification.md](jwt-verification.md) for the full breakdown.

## Calling a downstream API

The downstream service uses [`examples/verify-token.php`](../examples/verify-token.php)
or its own variant to verify the JWT. Typical pattern on the consumer side:

```php
$claims = $auth->verify($jwt, $auth->configuration->clientId);
$claims->requireServiceToken();
$claims->requireRole('deploy.admin');
```

Identifying which service called you:

```php
$serviceClientId   = $claims->clientId;     // e.g. "svc_xxxx"
$serviceClientName = $claims->clientName;   // human-readable name, e.g. "ci-bot"
```

Useful for audit logs.

## Secret rotation

When you rotate the client secret:

1. In the admin UI, click **Reset secret** on the client — the server
   generates a new secret and shows it once.
2. Store the new secret in your secret manager.
3. Deploy / restart your service. There is no overlap window — the old
   secret stops working the moment the new one is generated.

For zero-downtime rotation, create a **second service account** with the
same roles, switch to it, then deactivate the old one.

## Token revocation

There is no token revocation endpoint. To invalidate active service tokens:

1. Revoke the client in the admin UI — new token requests will fail.
2. Active tokens stay valid until their `exp` (default 1 hour).

Plan ahead by keeping access token TTLs short for sensitive service
accounts.

## Common errors

| Symptom                                                  | Cause                                                            |
|----------------------------------------------------------|------------------------------------------------------------------|
| `OAuthServerException: invalid_client`                   | Wrong `client_id`/`client_secret`, or the client has been revoked |
| `OAuthServerException: unauthorized_client`              | Client doesn't have the `client_credentials` grant enabled        |
| `OAuthServerException: invalid_scope`                    | Requested scope not allowed for this client                       |
| `TokenVerificationException: Unexpected JWT typ ...`     | Token was not minted as an RFC 9068 `at+jwt` — usually a non-stromcom server or an id_token fed in by mistake |
| `TokenVerificationException: JWT is missing required string claim "client_id"` | Server didn't emit `client_id` — non-RFC-9068 token        |
| Sporadic `401` from downstream API                       | Token expired mid-request — increase `refreshLeewaySeconds` in your cache |
