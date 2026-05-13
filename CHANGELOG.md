# Changelog

All notable changes to this package are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this package adheres to [Semantic Versioning](https://semver.org/).

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
