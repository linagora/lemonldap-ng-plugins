# Changelog

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
