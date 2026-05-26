# Changelog

All notable changes to this package are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this package adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0] — 2026-05-26

Realigns the verifier with the relevant specs (RFC 9068 for access tokens,
OIDC Core 1.0 §3.1.3.7 for id_tokens, RFC 8725 §3.11 for token-type
confusion). Breaking.

### Added

- `Client::verifyIdToken(string $jwt, string $expectedNonce): Claims` — OIDC
  Core 1.0 §3.1.3.7 id_token validation: signature, `iss`, `aud == client_id`,
  `azp` check when `aud` is multi-valued or `azp` present, `exp`/`iat`,
  timing-safe `nonce` binding. `typ=at+jwt` is rejected to prevent
  access-token / id-token confusion (RFC 8725 §3.11).
- `TokenVerifier::verifyIdToken()` — same as above at the lower level.

### Changed (BREAKING)

- `Client::verify()` and `TokenVerifier::verify()` now enforce the JOSE
  `typ` header (MUST be `at+jwt` or `application/at+jwt`, RFC 9068 §2.1) and
  check presence of the RFC 9068 §2.2 REQUIRED claims `sub`, `client_id`,
  `jti`, `iat`. Tokens without these are rejected.
- `Client::verify()` signature changed: `verify(string $jwt, string $expectedAudience)`.
  The audience is **required and a single string** — the previous nullable
  `array` form with an implicit `clientId` default is gone. Pass
  `$auth->configuration->clientId` for confidential clients validating their
  own tokens, or the resource server's own audience identifier otherwise.
- `TokenVerifier::verify()` signature changed to `verify(string $jwt, string $expectedAudience)`.

### Removed (BREAKING)

- The `token_use` requirement in `verify()`. RFC 9068 does not define
  `token_use`; requiring it tied the SDK to a stromcom-specific extension.
  `Claims::$tokenUse` is preserved (now nullable) and the
  `Claims::isUser()` / `isService()` / `requireUserToken()` /
  `requireServiceToken()` helpers still work for callers that want to
  discriminate by it explicitly.

### Migration

```diff
- $claims = $auth->verify($jwt);
+ $claims = $auth->verify($jwt, $auth->configuration->clientId);

- $claims = $auth->verify($jwt, expectedAudiences: ['svc_a']);
+ $claims = $auth->verify($jwt, 'svc_a');

# New: verify the id_token after exchangeCode()
+ $auth->verifyIdToken($tokens->idToken, $sessionNonce);
```

If you relied on the `token_use missing` check to reject older tokens,
either call `$claims->requireUserToken()` / `requireServiceToken()`
explicitly, or upgrade the auth server.

## [1.2.0] — 2026-05-26

### Changed

- `Client::beginAuthorization()` now auto-generates a `nonce` whenever `openid`
  is in the requested scope and adds it to the authorization request. The
  return tuple gained a fourth element — `$nonce` (string when `openid` is in
  scope, `null` otherwise). Existing `[$url, $pkce, $state]` destructures keep
  working; persist the nonce alongside `state` and verify it against the
  `nonce` claim of the returned id_token.

## [1.1.0] — 2026-05-14

### Added

- `Claims::$givenName` / `Claims::$familyName` — OIDC `given_name` / `family_name`
  claims (scope `profile`). The auth server now stores `given_name` and
  `family_name` separately from the display `name`.
- `Claims::$phoneNumber` / `Claims::$phoneNumberVerified` — OIDC `phone_number`
  and `phone_number_verified` claims under the new `phone` scope. Request
  `scope=phone` at `beginAuthorization()` to receive them.

### Notes

- All new claims are nullable; tokens issued without the relevant scope (or by
  pre-1.1 servers) keep them as `null` — no breaking change for consumers that
  only read `email` / `name` / `roles` / `groups`.

## [1.0.0] — 2026-05-13

Initial public release.

### Added

- `Client::beginAuthorization()` — build Authorization Code + PKCE URL with
  `state` and `Pkce` pair.
- `Client::exchangeCode()` — exchange authorization code for `TokenSet`.
- `Client::refresh()` — refresh access token (rotation supported).
- `Client::clientCredentials()` — machine-to-machine flow.
- `Client::userInfo()` — call `/me` with a Bearer token.
- `Client::verify()` — local JWT verification via JWKS.
- `Client::logoutUrl()` — build end-session URL.
- `Client::discover()` — fetch OIDC discovery document.
- `Claims` value object with rich API:
  `hasRole`, `hasAnyRole`, `hasAllRoles`, `hasProjectRole`, `rolesForProject`,
  `hasGroup`, `hasAnyGroup`, `hasAllGroups`, `hasScope`, `requireRole`,
  `requireAnyRole`, `requireGroup`, `requireScope`, `requireUserToken`,
  `requireServiceToken`, `isExpired`, `secondsUntilExpiration`,
  `displayName`, `audience`, `claim`.
- `TokenSet` with `isExpired`, `authorizationHeader`.
- `Pkce::generate()` and `Pkce::challengeFor()`.
- `TokenVerifier` with strict RFC 9068 enforcement (`iss`, `token_use`, `aud`).
- `JwksCacheInterface` with `InMemoryJwksCache`, `ApcuJwksCache` and `FileJwksCache` implementations.
- `HttpClientInterface` with `CurlHttpClient` default implementation.
- Exception hierarchy: `AuthClientException` (base), `ConfigurationException`,
  `TransportException`, `OAuthServerException`, `TokenVerificationException`,
  `AuthorizationException`.

### Technical decisions

- **JWT parsing and validation via `lcobucci/jwt: ^5.5`.** The auth server
  uses the same library transitively (through `league/oauth2-server`), so
  both ends share the same JWT interpretation. `firebase/php-jwt` was
  rejected due to current composer audit advisories.
- **JWK→PEM bridge in `Internal/JwkRsaKey`.** `lcobucci/jwt` accepts PEM keys
  only; JWKS publishes JWK. The bridge emits standard ASN.1
  SubjectPublicKeyInfo (≈70 LoC).
- **In-house PSR-20 `SystemClock`.** Avoids pulling `lcobucci/clock` for a
  one-method class.
- **Strict mode by default.** `iss` and `token_use` claims are required;
  missing or empty values raise `TokenVerificationException`.
- **JWKS cache `kid`-rotation.** On `kid` miss, the cache is invalidated
  and re-fetched once automatically before failing — supports key rotation
  without restart.
- **Defensive parsing of optional `scopes` shapes.** Accepts both
  whitespace-separated string and `list<string>`.
