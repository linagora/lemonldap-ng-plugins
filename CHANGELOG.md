# Changelog

## v0.1.14 - (Unreleased)

### Store / packaging

- Sync `linagora-lemonldap-ng-store` with the upstream LLNG #3580 branch:
  store now understands an `autoload` field in `plugin.json` and drops a
  JSON rule into `/etc/lemonldap-ng/autoload.d/` instead of editing
  `customPlugins` when `--activate` is used.
- Ship the upstream `::Plugins::Autoloader` as part of the store
  package (back-port for LLNG < 2.24.0) and register it in
  `customPlugins` at `configure` time, so plugins installed from the
  store load automatically without any manual config edit.
- Autoload rules are now strictly conditional: each entry has a mandatory
  `condition` (same grammar as `@pList` keys) and `module` pair; the
  plugin loads only when the condition is truthy against the running
  configuration. Plugins without a natural trigger key (`reports`,
  `mail-autodiscover`) keep the `customPlugins` path with `--activate`.
- `llng-build-manager-files` now warns (instead of failing silently) when
  an `insert_after`/`insert_before` reference is missing, and both fall
  back to append-at-end.

### New plugins

- **vault-conf-backend**: LemonLDAP::NG configuration backend storing the
  LLNG configuration in OpenBAO / HashiCorp Vault via the KV v2 secret
  engine. Installs `Lemonldap::NG::Common::Conf::Backends::OpenBAO`
- **oidc-jar**: RFC 9101 (JWT-Secured Authorization Request) full profile on
  top of LLNG's OIDC Core request object support. Adds JWE decryption of
  request objects, hardened `request_uri` fetching (timeout / Content-Type
  / size), validation of `iss` / `aud` / `exp` / `nbf` / `iat` / `jti`
  claims (with anti-replay cache), RFC 9101 error codes, per-RP
  "require signed request object" enforcement, and advertises
  `request_object_*_values_supported` / `require_signed_request_object`
  in discovery.

## v0.1.13 2026-04-17

### New plugins

- **oidc-global-scopes**: define OIDC scopes globally for all relying
  parties, with optional claim-to-session-attribute mapping. Two new
  config parameters under OIDC Service > Scopes:
  `oidcServiceGlobalExtraScopes` (scope → claims) and
  `oidcServiceGlobalClaimMapping` (claim → session attribute).
  Claim resolution falls back from per-RP Exported Attributes to
  the global mapping, then to the identity. Requires LLNG ≥ 2.23.0.

### New companion Debian package

- **linagora-llng-crowdsec-filters**: ships a corpus of
  CrowdSec-compatible HTTP filters to
  `/var/lib/lemonldap-ng/crowdsec-filters/` for use with LLNG's
  `crowdsecFilters` option. Includes HTTP probing scenarios
  (`http-sqli-probing`, `http-xss-probing`), log4j / Jira / ThinkPHP
  CVE triggers, and curated `url_*` / `urlskip_*` block/skip lists.
  A scheduled workflow refreshes `http-cve-probing` weekly from
  CrowdSec's trendy CVE URIs feed. MIT-licensed content imported
  from crowdsec.net.

### Tests

- **oidc-global-scopes**: 39 tests (global scope enrichment,
  `allowOnlyDeclaredScopes` preservation, explicit claim mapping,
  identity fallback, per-RP declaration precedence, silent skip of
  unresolvable claims).

### Documentation

- Reference the `oidc-global-scopes` plugin and the
  `linagora-llng-crowdsec-filters` companion package in the main
  README.

## v0.1.12 2026-04-17

### Bug fixes

- **ssh-ca**: Fix signed keys not displayed in mycerts endpoint.
  `_storeCertificate` was reading existing certificates from
  `$req->sessionInfo` (not populated on auth route requests) instead of
  `$req->userData`, causing each new signing to overwrite the previous
  certificate list.
- **ssh-ca**: Fix RSA public key conversion when `Crypt::PK::RSA` lacks
  `export_key_openssh`. Falls back to `ssh-keygen -i -m PKCS8`.

### Improvements

- **ssh-ca**: Fix hardcoded key filename in post-signing instructions.
  Explain the `-cert.pub` naming convention instead.

### Tests (1048 total across 9 plugins)

- **ssh-ca**: 248 tests (public endpoints, signing, security, mycerts
  accumulation, cross-session persistence, admin listing, revocation, KRL)
- **pam-access**: 300 tests (token generation, device enrollment, verify,
  authorize with server groups and sudo rules, offline mode, bastion JWT)
- **oidc-ciba**: 17 tests (metadata, backchannel auth, poll/approve/deny,
  callback auth, ping mode, direct auth)
- **oidc-par**: 115 tests (server-side PAR, client-side PAR, private_key_jwt)
- **oidc-federation**: 52 tests (entity config, discovery, list, fetch,
  end-to-end federated RP enrollment)
- **oidc-jarm**: 17 tests (full JARM flow with response_mode=query.jwt)
- **pacc**: 40 tests (PACC metadata endpoint, disabled/no-servers states)
- **matrix**: 123 tests (online and offline Matrix token exchange)

### Documentation

- **ssh-ca**: Expanded README with full configuration, endpoint details,
  KRL management, and server-side SSH setup
- **captchetat**: Note AGPL-3.0 license in README
- Reference Open Bastion project in main README

### CI

- Install all sibling plugins (lib + templates) for each test job
- Override built-in LLNG modules with plugin versions
- Trigger push CI only on main (avoid duplicate runs on PRs)
- Add per-plugin apt build dependencies via plugin.json

## v0.1.11 - 2026-04-16

### Bug fixes

- **ssh-ca**: Fix "Route ssh redefined" warning. `addAuthRouteWithRedirect`
  was overwriting the `ssh` unauth route HASH (containing `/ssh/ca` and
  `/ssh/revoked` sub-routes) with a leaf CODE ref. Replace with explicit
  `addAuthRoute` + `addUnauthRoute` using `'*'` sub-routes, and chain all
  route registrations.
- **pam-access**: Fix "Conflict detected between 2 extensions" error.
  Same root cause: `addAuthRouteWithRedirect` set `pam` as a CODE leaf
  in unauth routes (for both GET and POST), then chained `addUnauthRoute`
  calls with POST sub-routes (`authorize`, `heartbeat`, etc.) conflicted
  with the existing CODE ref.

## v0.1.10 - 2026-04-13

### Improvements

- **ssh-ca**: Display user's existing certificates on /ssh page with
  status (active/expired/revoked). New `GET /ssh/mycerts` endpoint.
  List refreshes automatically after signing a new certificate.
- **pam-access**: Remove legacy `pamAccessServerGroups` configuration.
  Only `pamAccessSshRules` and `pamAccessSudoRules` are used now.

### Bug fixes

- **pam-access**: Fix token generation (missing POST /pam route).
- **Debian packages**: Fix portal translations not being merged at
  install time (replace Python3 with Perl in postinst scripts).
- **manager-overrides**: Fix ctree/tree paths for 8 plugins. Options
  now appear correctly in the Manager UI:
  - oidc-device-authorization, oidc-device-organization,
    oidc-scope-applications: insert into RP security options
  - oidc-jarm: insert JARM algorithms into RP algorithms section
  - oidc-par: insert PAR option into RP security options
  - oidc-ciba: insert CIBA option into RP advanced options
  - external-menu: fix tree path to advancedParams/portalRedirection
  - fixed-logout-redirection: fix tree path to advancedParams/forms

## v0.1.8 - 2026-04-13

### Improvements

- **pam-access**, **ssh-ca**: Replace MenuTab with standalone pages
  (`addAuthRouteWithRedirect` + `sendHtml`). Fixes incompatibility with
  `external-menu` plugin. Access control is now handled via portal
  `locationRules`. Remove `portalDisplayPamAccess` and `portalDisplaySshCa`
  configuration parameters.

## v0.1.7 - 2026-04-10

### Security

- Reject symlinks and hardlinks in plugin archives
- Sanitize archive and signature filenames from remote store index
- Validate Perl module names before `require` (prevent code injection)
- Validate `customPlugins` module names against `Lemonldap::NG::` namespace
- Replace shell-interpolated command execution with safe list-form calls
- Restrict `manager-overrides/` to JSON-only in `llng-build-manager-files`

## v0.1.6 - 2026-04-10

### New plugins (beta)

- **oidc-federation**: OpenID Connect Federation (server side). Entity
  Configuration endpoint, trust chain resolution, subordinate statement
  issuance, metadata policy enforcement, and automatic RP resolution via
  federation trust anchors.

## v0.1.5 - 2026-04-09

### New plugins (beta)

- **captchetat**: CaptchEtat captcha module — integrates the French government
  CAPTCHA service (PISTE platform) with OAuth2 authentication, image display
  and audio playback for accessibility.

## v0.1.4 - 2026-04-08

### New plugins (beta)

- **twake**: Twake integration — `.well-known/twake-configuration` endpoint
  and LDAP-based applicative account management.
- **oidc-scope-applications**: OIDC `applications` scope exposing the portal
  application menu in the userinfo response.
- **fixed-logout-redirection**: Force redirect to a fixed URL after logout,
  bypassing the default portal logout page.
- **external-menu**: Redirect authenticated users to an external URL instead
  of showing the portal menu (LLNG < 2.23.0, included in core after).

### New Debian packages

- **linagora-llng-build-manager-files**: backport of `llng-build-manager-files`
  with `--plugins-dir` support for LLNG < 2.23.0. Required when using plugins
  with manager-overrides on older versions.

### Changed

- Plugins use `Pre-Depends` on the store so dpkg triggers are registered
  before plugin files are installed
- Store rebuild now fails with actionable error when the Manager is installed
  but `llng-build-manager-files` is missing

## v0.1.3 - 2026-04-07

### New plugins (beta)

- **pacc**: PACC — Provider Automatic Configuration for Clients
  (draft-ietf-mailmaint-pacc). Provides `/.well-known/pacc.json` endpoint
  for mail client autoconfiguration (IMAP, SMTP, JMAP, CalDAV, CardDAV)
  with OAuth2 issuer info. Enhances OIDC dynamic registration for native
  clients and public clients.
- **oidc-par**: OAuth 2.0 Pushed Authorization Requests (RFC 9126).
  Provider-side PAR endpoint + client-side PAR support for remote OPs.
  Advertises PAR in OIDC discovery via `oidcGenerateMetadata` hook.
- **oidc-ciba**: OpenID Connect Client-Initiated Backchannel Authentication.
  Poll and ping delivery modes, external authentication channel, CIBA grant
  type on the token endpoint.
- **oidc-device-authorization**: OAuth 2.0 Device Authorization Grant
  (RFC 8628). Device code endpoint, user verification portal page, PKCE
  support.
- **oidc-device-organization**: Organization device ownership extension for
  RFC 8628. Tokens identify the client application instead of the approving
  admin. Requires oidc-device-authorization.
- **pam-access**: PAM access token generation and authorization for SSH/sudo.
  Portal interface, server-to-server endpoints, per-group SSH/sudo rules,
  heartbeat monitoring, offline mode.
- **ssh-ca**: SSH Certificate Authority. Portal interface for signing user
  SSH public keys, admin interface for certificate management and revocation,
  KRL support.

### Changed

- **oidc-jarm**: Use `oidcGenerateMetadata` hook to advertise JARM support
  in OIDC discovery (no core patch needed)
- `llng-build-manager-files`: `tree` now supports arrays for multiple
  insertions in a single manager-overrides file
- Debian repo: add `index.html` landing page

## v0.1.2 - 2026-04-01

### Added

- Debian repo

## v0.1.1 - 2026-03-26

### New plugin

- **json-file**: JSON file-based Auth/UserDB backend for development and
  testing (#2). Inherits from Demo, loads users, passwords and groups from
  a JSON file configured via Manager (`jsonFileUserPath`) or
  `LLNG_JSONUSERS` environment variable. Includes manager-overrides to
  add JsonFile to the authentication and userDB select dropdowns.

## v0.1.0 - 2026-03-24

Initial store release
