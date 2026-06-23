# PAM Access - Token Generation and Authorization

This plugin provides PAM integration for LemonLDAP::NG, allowing users to
generate temporary access tokens for SSH and other PAM-enabled services.

## Features

- **Portal interface** (`/pam`): users generate short-lived one-time tokens,
  either from the web UI or with the [`llng` client](https://github.com/linagora/simple-oidc-client)
  `pam_token` command.
- **Token verification** (`/pam/verify`): server-to-server endpoint for PAM
  modules, with optional SSH fingerprint binding (see below).
- **Authorization** (`/pam/authorize`): server-to-server endpoint for SSH /
  sudo rules, with optional SSH fingerprint binding.
- **Bastion token** (`/pam/bastion-token`): a bastion server can obtain a
  signed JWT that proves to a downstream backend that the user is connected
  through a trusted bastion.
- **Server groups mapping**: the authoritative group of an enrolled server
  can be pinned to its OIDC `client_id`, preventing a server from claiming
  another group's permissions.
- **Heartbeat monitoring**: track PAM server health.
- **Offline mode**: cache authorization decisions for disconnected servers.
- **OIDC Device Authorization Grant**: secure server enrollment.

## Requirements

- LemonLDAP::NG >= 2.23.0
- OIDC issuer must be enabled
- An OIDC RP configured for PAM access (default name: `pam-access`)

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.24.0)_ or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```bash
sudo lemonldap-ng-store install pam-access
```

Manually: copy `lib/` into your Perl `@INC` path, copy `portal-templates/`
and `portal-static/` into the portal directories, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-overrides.d/`, add `::Plugins::PamAccess` to
`customPlugins`, and run `llng-build-manager-files`.

## Configuration

In the Manager under **General Parameters** > **Plugins** > **PAM Access**:

| Parameter                              | Description                                                                                                                                                                              | Default   |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| `pamAccessActivation`                  | Enable the plugin                                                                                                                                                                        | `0`       |
| `pamAccessTokenDuration`               | Default user token TTL (seconds)                                                                                                                                                         | `600`     |
| `pamAccessMaxDuration`                 | Maximum user token TTL (seconds)                                                                                                                                                         | `3600`    |
| `pamAccessSshRules`                    | Per-group SSH authorization rules                                                                                                                                                        | `{}`      |
| `pamAccessSudoRules`                   | Per-group sudo authorization rules                                                                                                                                                       | `{}`      |
| `pamAccessExportedVars`                | Session attributes to expose to PAM modules                                                                                                                                              | `{}`      |
| `pamAccessServerGroups`                | Authoritative mapping `client_id → server_group`. When non-empty, `/pam/authorize` and `/pam/bastion-token` enforce the mapping and reject mismatches.                                   | `{}`      |
| `pamAccessBastionGroups`               | Comma-separated list of server groups allowed to call `/pam/bastion-token`                                                                                                               | `bastion` |
| `pamAccessBastionJwtTtl`               | Bastion JWT validity in seconds                                                                                                                                                          | `300`     |
| `pamAccessBastionMaxSeenAge`           | Maximum age (seconds) of the `_pamSeen` marker accepted by `/pam/bastion-token`. Default 1 week. Set to `0` to disable the age check.                                                    | `604800`  |
| `pamAccessOfflineEnabled`              | Enable offline mode (boolOrExpr)                                                                                                                                                         | `0`       |
| `pamAccessOfflineTtl`                  | Offline authorization cache TTL (seconds)                                                                                                                                                | `86400`   |
| `pamAccessHeartbeatRequired`           | Require a recent heartbeat for `/pam/authorize`                                                                                                                                          | `0`       |
| `pamAccessChoice`                      | Choice sub-module (must match an `authChoiceModules` entry, e.g. `1_LDAP`) used by `/pam/authorize`, `/pam/userinfo` and `/pam/bastion-token`. Leave empty when Choice auth is not used. | `""`      |
| `pamAccessBastionCertPinSourceAddress` | Pin the ephemeral cert issued by `/pam/bastion-cert` to the bastion's IP (`source-address` critical option). See the note below.                                                         | `0`       |

> **Recommendation — `pamAccessBastionCertPinSourceAddress`**
>
> When enabled, the certificate issued by `/pam/bastion-cert` carries a
> `source-address` critical option pinning it to the bastion's IP, so a leaked
> certificate is only usable from the bastion that requested it (enforced
> natively by `sshd`). **Enable it whenever there is no NAT/PAT between the
> bastions and the portal** — it is a free, transparent hardening of the
> bastion-to-backend hop.
>
> Keep it disabled (the default) when the address LemonLDAP::NG observes does
> not match the bastion's SSH egress address — portal behind a reverse proxy,
> multi-homed bastion, or NAT/PAT — otherwise legitimate certificates would be
> rejected by the backend.

## Endpoints

### User endpoints (portal authentication)

| Method | Path   | Description                                              |
| ------ | ------ | -------------------------------------------------------- |
| GET    | `/pam` | Web UI to generate a short-lived one-time token          |
| POST   | `/pam` | Generate a one-time token (`{token, login, expires_in}`) |

The [`llng` client](https://github.com/linagora/simple-oidc-client) wraps this
`POST /pam` call in its `pam_token` command, a scriptable alternative to the web
UI. The requested TTL is passed as `{"duration": <seconds>}` (CLI flag
`--pam-duration`, default `600`), capped by `pamAccessMaxDuration`.

Each `/pam` POST also stamps a `_pamSeen` marker on the user's persistent
session. This marker makes the user eligible for `/pam/bastion-token` (see
below).

### Server-to-server endpoints (OIDC Bearer token)

| Method | Path                 | Description                                              |
| ------ | -------------------- | -------------------------------------------------------- |
| POST   | `/pam/verify`        | Validate and consume a one-time user token               |
| POST   | `/pam/authorize`     | Check SSH/sudo rules for a given `user`/`host`/`service` |
| POST   | `/pam/heartbeat`     | Record a server liveness ping                            |
| POST   | `/pam/userinfo`      | Look up user info for NSS / PAM caches                   |
| POST   | `/pam/bastion-token` | Mint a JWT proving a bastion hosts a legitimate user     |

All server-to-server endpoints require a Bearer access token obtained via
the OIDC Device Authorization Grant (`grant_type=device_code`) with scope
`pam:server` (or `pam`).

### Optional SSH fingerprint binding (`/pam/verify`, `/pam/authorize`)

If the request body contains a `fingerprint` field, the plugin resolves the
user's persistent session and confirms that an SSH CA certificate with that
fingerprint exists, is not revoked, and has not expired. This binds a PAM
token (and the subsequent authorization decision) to a specific SSH key,
even if the SSH server's KRL is stale.

- The fingerprint must be `SHA256:<base64>`; leading/trailing whitespace is
  tolerated. Malformed input returns HTTP 400 with
  `PAM_AUTH_SSH_FP_MALFORMED` / `PAM_AUTHZ_SSH_FP_MALFORMED`.
- On success the matched `ssh_cert_label` and `ssh_cert_serial` are
  surfaced (in `attrs` for `/pam/verify`, at the top level for
  `/pam/authorize`).

### Server-group enforcement (`pamAccessServerGroups`)

- If the mapping is non-empty, `/pam/authorize` and `/pam/bastion-token`
  ignore any `server_group` from the request body and use the mapped
  value. Unknown `client_id`s are rejected. A body `server_group` that
  contradicts the mapping yields HTTP 403 +
  `PAM_AUTHZ_SERVER_GROUP_MISMATCH`.
- If the mapping is empty, the plugin falls back to the legacy behaviour
  (group from the body) and emits a warning log — existing deployments
  keep working until they configure the mapping.

### Bastion-token eligibility

`/pam/bastion-token` signs a JWT with `sub = $user` only if **both** hold:

1. The user has a `_pamSeen` marker on this portal (i.e. they have
   generated a PAM token via `/pam` or consumed one via `/pam/verify`).
2. The marker is younger than `pamAccessBastionMaxSeenAge` (default
   1 week). Set it to `0` to disable the TTL check.

Audit codes emitted on refusal: `PAM_BASTION_TOKEN_UNKNOWN_USER`,
`PAM_BASTION_TOKEN_STALE_MARKER`.

Bastions remain responsible for only calling `/pam/bastion-token` for
users whose SSH session they are actively proxying; the portal only
checks the identity is known and fresh on its side.

### Probe mode (`"probe": true`)

A bastion can self-identify the `bastion_id` it would be assigned by
POSTing `{"probe": true}` (no `user` required). The portal returns the
`bastion_id` (derived from the token's `client_id`) and `server_group`
directly, skipping the `_pamSeen` recency gate and **without** minting a
usable JWT:

```json
{ "bastion_id": "...", "server_group": "...", "probe": true }
```

The device-grant token, scope and `pamAccessBastionGroups` membership
checks still apply, so only a legitimate bastion can learn its own id.
This is what `ob-bastion-id` uses to identify itself; a probe vouches
for no real user, so the per-user freshness check does not apply.

## See Also

- [PAM Access documentation](https://lemonldap-ng.org/documentation/latest/pamaccess)
- [SSH CA plugin](../ssh-ca/README.md) — issues the SSH certificates whose
  fingerprints are bound by `/pam/verify` / `/pam/authorize`.
