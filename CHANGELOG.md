# Changelog

## v0.1.20 - 2026-04-22

Touched plugins bumped to **0.1.20** in lockstep: `ssh-ca`, `pam-access`.
Hardening + perf release, plus a new local-test MCP toolchain that now
drives CI.

### ssh-ca

- **Enforcment - principal-source**: each `$var` in
  `sshCaPrincipalSources` must yield at most one principal token, but
  attribute values containing `,`, whitespace or CR/LF would split into
  multiple tokens downstream (whitespace is the template's own
  separator, `,` is `ssh-keygen -n`'s separator, CR/LF would poison
  audit logs).
- **Perf - pure-Perl SSH fingerprint**: each `/ssh/sign` was forking
  `ssh-keygen -l -E sha256` (with a tempdir + pubkey-on-disk) just to
  compute the SHA256 fingerprint — ~10–30 ms of fork/exec/cleanup per
  signature. Reimplemented with `Digest::SHA` + `MIME::Base64` (both
  LLNG core deps); verified bit-for-bit against `ssh-keygen` on
  `ssh-ed25519`, `ssh-rsa` and `ecdsa-sha2-nistp256` keys.
- **Perf - reuse decoded `_sshCerts`**: `sshCaSign` already decoded
  `userData->{_sshCerts}` once for the label-uniqueness check, then
  `_storeCertificate` re-ran `from_json` on the same blob. The decoded
  arrayref is now threaded through via a new `existing` named arg
  (one JSON parse saved per `/ssh/sign`, and the two decode paths can
  no longer disagree after an in-memory mutation).

### pam-access

- **Refactor - single SHA256 fingerprint validator**
- **Perf - one persistent-session load per `/pam/verify`**
  CLI-driven CI links them only when running pam-access's tests.

### Tooling — new local-test MCP server + CLI

- **`mcp/`** (new): Node.js toolchain that automates the plumbing to
  run a plugin's Perl test suite against a LemonLDAP::NG checkout.
  Two entry points share `lib.js`:
  - **`server.js`**: MCP server _(auto-loaded by Claude Code and other
    MCP-aware clients via `.mcp.json`)_.
  - **`cli.js`** _(`llng-plugins-test` npm bin)_: standalone CLI for
    humans and CI; `prove`'s exit code is propagated.
- **CI (`.github/workflows/test.yml`)** rewritten on top of
  `mcp/cli.js`

## v0.1.19 - 2026-04-21

Touched plugin bumped to **0.1.19**: `ssh-ca`. Multi-portal support
for the SSH CA (issue #9).

### ssh-ca

- **Feature - multi-portal KRL replication via message broker**: every
  revocation (self-revoke, admin revoke, resign-supersede path) is now
  also published as a `sshCaRevoke` event on the LLNG message broker.
- **Feature - stateless serial generation**: the per-node flock-based
  counter file is gone. Serials are now derived from `Time::HiRes`
  (µs-precision wall clock) plus a 3-digit random tail, with a
  per-process monotonic guard so intra-process collisions are
  impossible even on coarse/NTP-adjusted clocks.
- **Feature - `sshca-rebuild-krl` cron script**: ships in
  `scripts/sshca-rebuild-krl`. To be used in cron jobs.

## v0.1.18 - 2026-04-21

Touched plugin bumped to **0.1.18**: `json-file`. Store and CI improvements.

### json-file

- **Export all JSON attributes into the session**: `UserDB::JsonFile`
  now overrides `setSessionInfo` to push every attribute present in the
  JSON file into the session, instead of relying on the `exportedVars`
  mapping (which defaulted to `uid` / `cn` / `mail` only). The parent
  `Demo::setSessionInfo` is still called afterwards, so existing
  `exportedVars` / `demoExportedVars` mappings can still rename or
  shadow specific keys. Useful for DR setups where the JSON mirrors a
  rich LDAP profile and every field (admin flag, mailbox, service ids,
  ...) must be available without duplicating each name in
  `exportedVars`.

### Store / packaging

- **`authPlugin` declaration for auth modules**: a plugin's
  `manager-overrides/*.json` can now declare itself at the top level
  via an `authPlugin` object (with `k`, `v`, and a `roles` list among
  `authentication`, `userDB`, `passwordDB`) instead of manually
  appending to each core select. `llng-build-manager-files` fans the
  entry out to the relevant `authentication` / `userDB` / `passwordDB`
  selects, to `authChoiceModules` (nested `authenticationLevel`, etc.)
  and to `combModules`, with per-key dedup. `json-file` migrated to
  this mechanism, which also fills `authChoiceModules` so it now shows
  up under authChoice.
- **Conflict detection**: when two extension files declare the same
  `authPlugin` key with a mismatching label or role set, the
  rebuilder now warns the maintainer instead of silently dropping the
  second declaration (dedup still keeps the first-seen entry).

## v0.1.17 - 2026-04-20

Security hardening release (findings from `/security-review`). Touched
plugins bumped to **0.1.17** in lockstep: `pam-access`,
`oidc-device-authorization`.

### pam-access

- **Fix - `/pam/authorize` confused deputy (HIGH)**: the endpoint no
  longer trusts a `server_group` supplied in the request body when the
  new `pamAccessServerGroups` mapping (`client_id → group`) is
  configured. Enrolled servers can no longer claim another group's
  permissions. Unmapped clients are rejected with
  `PAM_AUTHZ_SERVER_GROUP_MISMATCH`. If the map is empty, the legacy
  body-controlled behaviour is preserved (with a one-shot warning log).
- **Fix - `/pam/bastion-token` impersonation (MEDIUM)**: the endpoint
  now refuses to mint a JWT for a user that has not recently
  interacted with pam-access on this portal. A `_pamSeen` marker is
  stamped in the user's persistent session when they generate a token
  via `/pam` or consume one via `/pam/verify`, and the marker is
  required (and fresh, per `pamAccessBastionMaxSeenAge`, default
  **1 week**) for `/pam/bastion-token` to succeed. Bastions remain
  responsible for only calling the endpoint for users they are
  actively proxying. New audit codes:
  `PAM_BASTION_TOKEN_UNKNOWN_USER`, `PAM_BASTION_TOKEN_STALE_MARKER`.
- **New config**: `pamAccessServerGroups`, `pamAccessBastionGroups`,
  `pamAccessBastionJwtTtl`, `pamAccessBastionMaxSeenAge` are now
  surfaced in the manager UI with EN/FR translations (previously the
  two bastion-group/TTL options were read at runtime but not
  documented / exposed).
- **Upgrade note**: after upgrade, any user who hasn't passed through
  `/pam` or `/pam/verify` in the last 7 days will be rejected by
  `/pam/bastion-token`. In the normal open-bastion flow this is fine
  (SSH login triggers `/pam/verify`), but admins with idle users can
  raise `pamAccessBastionMaxSeenAge` or set it to `0` to disable the
  age check.

### oidc-device-authorization

- **Fix - stored XSS in `/device` approval page (MEDIUM)**: `SCOPE`,
  `CLIENT_ID`, `USER_CODE`, and `MSG` now go through
  `ESCAPE="HTML"` in `device.tpl`. Before the fix, a malicious RP (or
  an attacker controlling the `scope` parameter of
  `POST /oauth2/device`) could plant HTML that would execute in the
  authenticated portal origin when a victim user approved the device.

### json-file

- **Fix** - do not put its parameters into authParams (special management)

### Docs

- Refreshed `plugins/pam-access/README.md` and
  `plugins/ssh-ca/README.md` to match the current endpoints, config
  parameters, request/response shapes, and fingerprint-binding
  workflow; cross-linked the two plugins.

## v0.1.16 - 2026-04-19

Touched plugins bumped to **0.1.16** in lockstep: `ssh-ca`, `pam-access`.

### ssh-ca

- **Key labels (mandatory, unique)**: the signing form now requires a
  human-readable name per key (e.g. `laptop-pro`). Labels must be unique
  within the user's active certificates; the same label can only reuse
  the same key fingerprint (re-signing). If omitted, the value falls
  back to the SSH public key's comment to remain compatible with
  pre-0.1.16 session records. The label is displayed in "My Certificates"
  next to the SHA256 fingerprint.
- **Dedup on re-signature**: signing the same SSH public key twice now
  replaces the previous record in the persistent session and revokes the
  superseded serial in the KRL. The list keeps a single entry per
  fingerprint.
- **User self-revocation**: new `POST /ssh/myrevoke` endpoint and per-row
  "Revoke" button in "My Certificates". Revoked serials are immediately
  published in the KRL.
- **Fix**: `sshca.js` referenced the unexported `translationFields`
  variable from `portal.js` and crashed with a `ReferenceError`,
  preventing "My Certificates" from rendering. Uses `window.translate()`
  now.
- **Sign response / mycerts**: expose `label` and `fingerprint` fields.

### pam-access

- **SSH fingerprint binding** (both `/pam/verify` and `/pam/authorize`):
  when the caller passes an optional `fingerprint` field, the plugin
  resolves the user's persistent session via `getPersistentSession`,
  confirms that an SSH CA certificate with that fingerprint exists, and
  rejects the request if it is missing, revoked, or expired. This binds
  a PAM token (and the associated authorization decision) to a specific
  SSH key even when the SSH server's KRL is stale, providing
  defence-in-depth for Open-Bastion. Matched `ssh_cert_label` and
  `ssh_cert_serial` are surfaced in the response (in `attrs` for
  `/pam/verify`, at the top level for `/pam/authorize`).
- The fingerprint input is trimmed and strictly validated against
  `SHA256:<base64>` before lookup; malformed values return HTTP 400 and
  emit a `PAM_AUTH_SSH_FP_MALFORMED` / `PAM_AUTHZ_SSH_FP_MALFORMED`
  audit entry so unbounded attacker-controlled input never reaches logs.

### Tests

- **ssh-ca** (270 tests total): label validation (mandatory + SSH-comment
  fallback), uniqueness 409, fingerprint round-trip, re-signature dedup
  with KRL publication, self-revocation flow (including 400 on
  already-revoked and 404 on unknown serial), cross-session persistence
  and per-user isolation.
- **pam-access** new `05-PamAccess-SshFingerprint.t`: `/pam/verify` and
  `/pam/authorize` paths without fingerprint (backward compat), with a
  matching fingerprint (accepted + cert details surfaced), with
  unknown / revoked / malformed fingerprints, and whitespace tolerance.

## v0.1.15 - 2026-04-19

No plugin source code changed in this release - plugin package versions
stay at **0.1.14**. Debian packaging only.

### Debian packaging

- **open-bastion-plugins** (new meta-package): pulls the LLNG plugins
  required by an open-bastion deployment (`pam-access`, `ssh-ca`,
  `oidc-device-authorization`, `oidc-device-organization`) plus
  `openssl` / `openssh-client`, and ships the
  `open-bastion-plugins-autoconfig` bootstrap helper.
- **open-bastion-plugins-autoconfig**: idempotent Perl helper that
  configures an LLNG instance for open-bastion (ACLs, virtual hosts,
  OIDC RP for the device flow, PAM-access / SSH-CA service options,
  `customPlugins` registration).

## v0.1.14 - 2026-04-18

All plugins modified by this release are bumped to **0.1.14** in lockstep:
`external-menu`, `fixed-logout-redirection`, `matrix-token-exchange`,
`oidc-ciba`, `oidc-device-authorization`, `oidc-device-organization`,
`oidc-federation`, `oidc-global-scopes`, `oidc-jar` (new),
`oidc-jarm`, `oidc-par`, `oidc-scope-applications`, `pacc`, `pam-access`,
`ssh-ca`, `twake`, `vault-conf-backend` (new).

### Store / packaging

- Store now understands an `autoload` field in `plugin.json` and drops a
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

- **captchetat**: CaptchEtat captcha module - integrates the French government
  CAPTCHA service (PISTE platform) with OAuth2 authentication, image display
  and audio playback for accessibility.

## v0.1.4 - 2026-04-08

### New plugins (beta)

- **twake**: Twake integration - `.well-known/twake-configuration` endpoint
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

- **pacc**: PACC - Provider Automatic Configuration for Clients
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
