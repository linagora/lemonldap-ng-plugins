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
- **Server groups mapping**: the authoritative group of an enrolled server
  can be pinned to its OIDC `client_id`, preventing a server from claiming
  another group's permissions.
- **Heartbeat monitoring**: track PAM server health.
- **Offline mode**: cache authorization decisions for disconnected servers.
- **OIDC Device Authorization Grant**: secure server enrollment.

## Requirements

- LemonLDAP::NG >= 2.23.2
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
| `pamAccessRequestSigningMode`          | Verify the client's `X-Signature-256` / `X-Timestamp` / `X-Nonce` headers: `off`, `optional`, `required`.                                                                                | `off`     |
| `pamAccessRequestSigningSecret`        | Shared secret, equal to the client's `request_signing_secret`.                                                                                                                          | `''`      |
| `pamAccessRequestSigningWindow`        | Accepted `X-Timestamp` skew in seconds, and the nonce replay-cache lifetime.                                                                                                            | `300`     |
| `pamAccessAllowedRps`                  | Comma-separated RP configuration keys allowed to call `/pam/*`. Empty accepts any device-grant token with a pam scope (historical behaviour). Setting it also forbids a self-declared bastion `server_group`. | `''`      |
| `pamAccessServerGroups`                | Authoritative mapping `client_id → server_group`. When non-empty, `/pam/authorize` enforces the mapping and rejects mismatches.                                                          | `{}`      |
| `pamAccessBastionGroups`               | Comma-separated list of server groups whose hosts may be vouched for as bastions                                                                                                         | `bastion` |
| `pamAccessOfflineEnabled`              | Enable offline mode (boolOrExpr)                                                                                                                                                         | `0`       |
| `pamAccessOfflineTtl`                  | Offline authorization cache TTL (seconds)                                                                                                                                                | `86400`   |
| `pamAccessHeartbeatRequired`           | Require a recent heartbeat from the calling server for `/pam/authorize` (see below)                                                                                                      | `0`       |
| `pamAccessInactiveThreshold`           | Maximum age (seconds) of that heartbeat, when `pamAccessHeartbeatRequired` is enabled                                                                                                    | `900`     |
| `pamAccessHeartbeatInterval`           | Heartbeat interval advertised to servers in the `/pam/heartbeat` response                                                                                                                | `300`     |
| `pamAccessChoice`                      | Choice sub-module (must match an `authChoiceModules` entry, e.g. `1_LDAP`) used by `/pam/authorize` and `/pam/userinfo`. Leave empty when Choice auth is not used. | `""`      |
| `pamAccessBastionCertPinSourceAddress` | Pin the ephemeral cert issued by `/pam/bastion-cert` to the bastion's IP (`source-address` critical option). When set and the observed address is unusable, the request is refused rather than served unpinned. See the note below. | `0`       |
| `pamAccessRequireFingerprint`          | Refuse `/pam/verify` and `/pam/authorize` when the caller supplies no SSH fingerprint, instead of falling back to the unbound behaviour.                                                  | `0`       |
| `pamAccessBastionVoucherUnboundTtl`    | Maximum lifetime of a voucher minted without a fingerprint, i.e. one that nothing binds to the user's SSO certificate expiry (seconds).                                                        | `900`     |

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

### Requiring a live server (`pamAccessHeartbeatRequired`)

By default a server may call `/pam/authorize` for as long as its access token
is valid, whether or not it still reports for duty. Enable
`pamAccessHeartbeatRequired` to additionally demand a heartbeat newer than
`pamAccessInactiveThreshold` (default 900s, three missed beats at the default
300s interval): a decommissioned, cloned or tampered-with machine then loses
its authority within the threshold instead of at token expiry.

`/pam/heartbeat` records the liveness marker on the refresh-token session it
beats against **and** on every access token it mints, so `/pam/authorize` can
read the _live_ value even when a server reuses one access token for its whole
lifetime.

Two consequences worth knowing before enabling it:

- a freshly enrolled server must beat once before it can authorize anybody —
  the plain device-grant token carries no marker;
- servers must actually run `ob-heartbeat` (or an equivalent) on a timer
  shorter than `pamAccessInactiveThreshold`.

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
session. Nothing reads it since `/pam/bastion-token` was removed; it is kept
as the trail a future "require a recent `/pam/verify` before sudo" policy
would need.

### Server-to-server endpoints (OIDC Bearer token)

| Method | Path                 | Description                                              |
| ------ | -------------------- | -------------------------------------------------------- |
| POST   | `/pam/verify`        | Validate and consume a one-time user token               |
| POST   | `/pam/authorize`     | Check SSH/sudo rules for a given `user`/`host`/`service` |
| POST   | `/pam/heartbeat`     | Record a server liveness ping                            |
| POST   | `/pam/userinfo`      | Look up user info for NSS / PAM caches                   |

All server-to-server endpoints require a Bearer access token obtained via
the OIDC Device Authorization Grant (`grant_type=device_code`) with scope
`pam:server` (or `pam`) — `/pam/heartbeat` authenticates through the
`refresh_token` of its request body instead of a header, but the same two
conditions apply to it. The scope is matched **exactly** against the
whitespace-separated values of the granted scope (RFC 6749 §3.3): `pam-x`,
`x-pam` and `pam:server:extra` are not `pam`.

A caller with no credential gets `401`; one that is not enrolled, or whose
token lacks the scope, gets `403`.

### Optional SSH fingerprint binding (`/pam/verify`, `/pam/authorize`)

If the request body contains a `fingerprint` field, the plugin resolves the
user's persistent session and confirms that an SSH CA certificate with that
fingerprint exists, is not revoked, and has not expired. This binds a PAM
token (and the subsequent authorization decision) to a specific SSH key,
even if the SSH server's KRL is stale.

- The fingerprint must be `SHA256:<base64>`; leading/trailing whitespace is
  tolerated. Malformed input returns HTTP 400 with
  `PAM_AUTH_SSH_FP_MALFORMED` / `PAM_AUTHZ_SSH_FP_MALFORMED`.
- With `pamAccessRequireFingerprint`, a request carrying *no* fingerprint is
  refused with HTTP 400 and its own codes,
  `PAM_AUTH_SSH_FP_REQUIRED` / `PAM_AUTHZ_SSH_FP_REQUIRED`. They are distinct
  from the malformed ones on purpose: "a caller sent garbage" and "a caller
  has not rolled out the fingerprint spool yet" are different operational
  situations and deserve different SIEM thresholds.
- On success the matched `ssh_cert_label` and `ssh_cert_serial` are
  surfaced (in `attrs` for `/pam/verify`, at the top level for
  `/pam/authorize`).

#### Where a bastion voucher is stored

A `/pam/authorize` on a bastion group mints a **voucher**: the proof, spent at
`/pam/bastion-cert`, that this user really connected to *this* bastion. It is
keyed on `(user, bastion_id)` and shared across the user's concurrent sessions
on that bastion, so a second login reuses the live nonce instead of rotating
it — rotating would invalidate the nonce already exported into the other
sessions' shells.

Each voucher lives in **its own session record** (`kind => PAMVOUCHER`), the
way the portal core stores an OIDC authorization code: on the global store,
with its lifetime carried in `_utime` so the regular session purge reclaims
it. It is deliberately not affected by `tokenUseGlobalStorage` or
`hashedSessionStore` — a voucher is minted on the node that answered
`/pam/authorize` and spent on whichever node answers `/pam/bastion-cert`, so a
node-local or differently-addressed copy would only ever be the wrong one.

Vouchers used to live in the user's persistent session, first as one
`_pamBastionVouchers` map and then as one key per bastion. Both are still read,
so nothing breaks on upgrade, and the next `/pam/authorize` carries the nonce
into a record. Neither is deleted: during a rolling upgrade an older node may
still be minting into them.

#### Hop-certificate binding window

Two kinds of certificate can match the fingerprint:

- **User SSO certificates** (`/ssh/sign`, stored per fingerprint under
  `_sshCert::<fp>`) — used when a
  user connects directly to a host (e.g. a standalone server). They are
  long-lived (default 30 days) and the binding accepts them until they expire
  or are revoked.
- **Ephemeral hop certificates** (`/pam/bastion-cert`) — minted per bastion→
  backend hop and registered per fingerprint. The SSH certificate itself is
  deliberately short-lived, just long enough for `sshd` to accept the
  connection.

For ephemeral hop certificates the binding must outlive the certificate: the
backend SSH session stays open far longer than the certificate's validity, and
a later `sudo` on that still-open session (with a fresh one-time token)
re-presents the same fingerprint. Acceptance is therefore gated on a separate
**binding window**, not on the certificate's own expiry — otherwise `sudo`
would start failing a couple of minutes into every session. Two independent
knobs control this (both code-level tunables read from the configuration, with
safe defaults; not surfaced in the Manager UI):

| Parameter                    | Description                                                                                                                                                      | Default       |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| `pamAccessBastionCertTtl`    | Validity of the ephemeral SSH certificate issued by `/pam/bastion-cert` (seconds) — the connection window enforced by `sshd`. Keep it short.                     | `120`         |
| `pamAccessBastionBindingTtl` | How long that certificate's fingerprint stays bindable for a still-open backend session (seconds), independent of the cert TTL. Raised to the cert TTL if lower. | `86400` (24h) |

Keeping `pamAccessBastionCertTtl` short limits the blast radius of a leaked hop
certificate (it can only open _new_ connections for that brief window — pair it
with `pamAccessBastionCertPinSourceAddress`), while `pamAccessBastionBindingTtl`
lets `sudo` keep working for the realistic lifetime of an open session. The
binding window only authorizes a `sudo` that **also** presents a fresh one-time
token, and it is server-side state (never transmitted), so a long value here
carries little risk. Revocation is always honored regardless of either value.

### Request signing (`pamAccessRequestSigningMode`)

open-bastion's PAM/NSS client signs every call to the portal when
`request_signing_secret` is configured. Until now nothing on this side read the
headers: the client signed, nothing checked, and the replay-protection chain
was a no-op (issue #81, linagora/open-bastion#188).

Wire format, as the client sends it:

| Header | Value |
| --- | --- |
| `X-Timestamp` | Unix seconds, decimal |
| `X-Nonce` | `<unix_ms>-<uuid-v4>` |
| `X-Signature-256` | `sha256=<64 lowercase hex>` |

```
message = <timestamp>.<nonce>.<method>.<path>.<body>
HMAC-SHA256, key = the raw bytes of the shared secret
```

Four literal `.` separators, always present; a bodyless request signs the empty
string. `<path>` carries no scheme, host or query string. `<body>` is the raw
bytes as sent, which is why the HMAC is computed before anything decodes the
JSON.

| Setting | Default | Meaning |
| --- | --- | --- |
| `pamAccessRequestSigningMode` | `off` | `off`, `optional`, `required` |
| `pamAccessRequestSigningSecret` | `''` | Must equal the client's `request_signing_secret` |
| `pamAccessRequestSigningWindow` | `300` | Accepted `X-Timestamp` skew, and the nonce cache lifetime |

**Rollout order.** Turning verification on is a breaking change for a fleet
where some hosts have the secret and some do not, so do it in three steps:
deploy with `optional`, roll the secret out to every host, then switch to
`required`. `optional` waives the requirement to *sign* — never the requirement
to sign *correctly*: a bad signature is refused in every mode but `off`.

Checks run **timestamp, then HMAC, then nonce**. The timestamp is first because
it is the cheapest and bounds both the replay window and the size of the nonce
store. The nonce claim is *last* because it is the only step that writes: it
must never run for a request whose signature does not verify, or an
unauthenticated caller could fill the shared session backend with one record
per request, and could burn the nonce of a request it had captured before the
legitimate retry arrived. The nonce cache is one session per nonce in the
shared backend, expiring with the window, so it works across workers and
nodes. Every refusal is 403 + `PAM_REQUEST_SIGNATURE_REFUSED` with a
machine-readable `reason`.

A configured mode with an empty secret refuses every request rather than waving
them through, and a mode value that is not one of `off` / `optional` /
`required` is treated as `required` with a once-per-worker warning — a typo
must not open the gate.

This is defence in depth **on top of** TLS, not a substitute for it. Do not
relax `verify_ssl` because of it.

### Which callers may reach `/pam/*` (`pamAccessAllowedRps`)

The caller gate checks that the presented token came from the device
authorization grant and carries a `pam` scope — and nothing else. But
`grant_type = device_code` is stamped for **every** RP using the device flow,
and the LLNG core performs no audience or RP check on an access token. So by
default any device-grant token with a `pam` scope reaches `/pam/*`; the cheap
attacker is not an unrelated application but a compromise of any ordinary
enrolled host in the same project, which already holds one (issue #50).

`pamAccessAllowedRps` lists the RP configuration keys — the same vocabulary as
`pamAccessRp` — that may call PAM:

```
pamAccessAllowedRps = pam-access, pam-bastions
```

It is **empty by default**, which keeps the historical behaviour so an upgrade
is not a rupture; a once-per-worker warning says so. A token from an unlisted
RP gets HTTP 403 + `PAM_CALLER_RP_REFUSED`, on all six endpoints.

The RP a token belongs to is resolved from `rp`, then `_clientConfKey`, then a
`client_id` lookup in the RP list. The three steps are not decoration: `rp` is
stamped on **access tokens only**, so the refresh token `/pam/heartbeat`
presents carries none, and the synthetic session built by
`oidc-device-organization` stamps `_clientConfKey` instead. A token whose
`client_id` matches no declared RP is treated as unlisted.

Setting it also turns on the second half of the fix, below.

### Server-group enforcement (`pamAccessServerGroups`)

- If the mapping is non-empty, `/pam/authorize` ignores any `server_group`
  from the request body and uses the mapped value. Unknown `client_id`s are
  rejected. A body `server_group` that contradicts the mapping yields
  HTTP 403 + `PAM_AUTHZ_SERVER_GROUP_MISMATCH`.
- If the mapping is empty, the plugin falls back to the legacy behaviour
  (group from the body) and emits a warning log — existing deployments
  keep working until they configure the mapping.
- **Except for bastion groups, once `pamAccessAllowedRps` is set.** In the
  legacy path a host could name itself a member of a `pamAccessBastionGroups`
  group and collect `(bastion_id, user)` vouchers for users it had never seen.
  The voucher binding is sound — and that is the problem: it binds to the
  *caller's own* device id, so the hop certificates go to the attacker. A
  deployment that has named its PAM relying parties can name its bastions too,
  so from then on a bastion group must come from `pamAccessServerGroups`;
  claiming one in the body yields 403 + `self_declared_bastion`. Ordinary
  groups are still taken from the body as before.

  In practice this means a bastion needs a `client_id` the map can key on. If
  one `client_id` covers a whole multi-group project, give the bastions their
  own — a host you trust to vouch for arbitrary users has to be
  distinguishable at enrollment.

## See Also

- [PAM Access documentation](https://lemonldap-ng.org/documentation/latest/pamaccess)
- [SSH CA plugin](../ssh-ca/README.md) — issues the SSH certificates whose
  fingerprints are bound by `/pam/verify` / `/pam/authorize`.
