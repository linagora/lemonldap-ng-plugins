# Changelog

## v0.3.10 - 2026-06-25

Touched plugins bumped to **0.3.10** in lockstep: `pam-access`. Theme: keep a
bastion hop certificate's fingerprint bindable for the whole backend SSH
session, not just for the certificate's own (short) validity.

### pam-access

- **Fix — bind the hop-cert fingerprint to a session window, not the cert
  TTL**. The ephemeral certificate issued by `/pam/bastion-cert` is
  deliberately short-lived (~120s, `pamAccessBastionCertTtl`) — just long
  enough for `sshd` to accept it at connection time. But the resulting backend
  SSH session lives much longer, and a later `sudo` (with a fresh one-time
  token) on that still-open session legitimately presents the same fingerprint.
  Gating `_checkSshFingerprint` on the cert's `expires_at` broke `sudo` a couple
  of minutes into every session. A separate binding window is now stored on the
  ephemeral record (`binding_expires_at`); `_checkSshFingerprint` and the prune
  loop accept/keep the fingerprint until that window elapses, falling back to
  `expires_at` for records minted before the field existed, while still
  returning the real `expires_at` so voucher minting keeps cert semantics.
- **New option `pamAccessBastionBindingTtl`** (default `86400`, i.e. 24h):
  how long a hop certificate's fingerprint stays bindable on the target
  backend, independent of `pamAccessBastionCertTtl`. Must be a positive
  integer; values below the cert TTL are raised to it. Only affects hop
  certificates (`/pam/bastion-cert`); direct `_sshCerts` certificates keep
  their own (longer) validity.

### Tooling & docs

- **`rpm/`** — add RPM build scripts (`build-rpms.sh`, `build-repo.sh`)
  to package the plugins and assemble a YUM/DNF repository.

## v0.3.9 - 2026-06-22

Touched plugins bumped to **0.3.9** in lockstep: `pam-access`. Theme: let
device-id enrollments resolve their authoritative server group when
`pamAccessServerGroups` is configured.

### pam-access

- **Fix — resolve the server group by OIDC `client_id`, not by `_deviceId`**.
  `pamAccessServerGroups` is keyed by `client_id` (one OIDC client per project,
  the group shared by every bastion of that project), while `_deviceId` is the
  per-device SHA-256 digest used as the audit / voucher-binding identity. Both
  `/pam/authorize` and `/pam/bastion-token` were passing `_deviceId` to the
  group resolver; since that digest is never a key of `pamAccessServerGroups`,
  every enrollment carrying a `_deviceId` was rejected with
  `Unknown enrolled server` even though its `client_id` was correctly mapped.
  The group is now resolved by `client_id`, with `_deviceId` kept as the
  audit / voucher-binding identity. Enforcement is unchanged — a caller-forged
  group that contradicts the mapping is still rejected. Adds
  `10-PamAccess-ServerGroupsDeviceId.t`, covering the previously-untested
  combination of `oidc-device-organization` (which stamps `_deviceId`) with a
  configured `pamAccessServerGroups`.

## v0.3.8 - 2026-06-17

Touched plugins bumped to **0.3.8** in lockstep: `oidc-device-organization`,
`oidc-device-authorization`, `pam-access`. Theme: give every enrolled host a
stable per-device identity when a whole project shares one OIDC `client_id`,
carry that identity end-to-end as the bastion/server id, and fix the
device-grant flow under `hashedSessionStore`.

### oidc-device-organization

- **Feature — stamp a per-device id (`_deviceId`) on the token session**. With
  one OIDC `client_id` per _project_, `client_id` no longer identifies an
  individual bastion, so the voucher binding and a backend's allowed-bastions
  allowlist had nothing unique to pin on. The synthetic per-device session id
  created at enrollment is now exposed as `_deviceId` for the rest of the
  chain to consume.
- **Security — derive `_deviceId` as a domain-separated digest, not the raw
  session id**. `_deviceId` is surfaced in tokens and API responses (e.g. the
  `/pam/bastion-token` probe), so stamping the raw synthetic session id leaked
  a live credential that could be replayed as a `lemonldap` cookie to
  impersonate the synthetic session. It is now `sha256_hex` of the session id
  with a domain-separating prefix — deterministic, unique per device, one-way,
  and guaranteed never to collide with a LLNG backend storage key (itself a
  `sha256_hex` under `hashedSessionStore`). `user_session_id` keeps pointing to
  the real session id for lookups.

### oidc-device-authorization

- **Feature — forward `_deviceId` into the access-token session**.
  `_generateTokens` carries `_deviceId` through to the access token so the
  per-device id reaches the PAM endpoints.
- **Fix — make device sessions work under `hashedSessionStore`**. The
  `user_code`/`device_code` device-authorization sessions are stored under a
  fixed id (the SHA-256 of the code) with `hashStore => 0`, but the lookups
  omitted `hashStore => 0`. With `hashedSessionStore` enabled,
  `getApacheSession` then searched under `sha256_hex(id)` and never found
  them: the verification page could not resolve the `user_code`, approval
  silently failed, and the token exchange returned `expired_token` — breaking
  every device-grant enrollment (including org-device bastion enrollment). All
  fixed-id session lookups/updates/removals now force `hashStore => 0` to match
  how the sessions are created; the real user SSO-session lookup is left to
  respect `hashedSessionStore`.

### pam-access

- **Feature — use the per-device id as `bastion_id`/`server_id` under a shared
  `client_id`**. `/pam/authorize`, `/pam/bastion-token` and `/pam/bastion-cert`
  now prefer `_deviceId` as the server/bastion id, falling back to `client_id`
  for legacy enrollments. `/pam/heartbeat` re-carries `_deviceId` into the
  refreshed access token so the id survives refreshes instead of reverting to
  the shared `client_id` after the first heartbeat.
- **Fix — reuse the bastion voucher across concurrent sessions**. A user who
  holds several SSH logins on the same bastion at once shares a single
  `(bastion_id, user)` voucher across them. Minting a fresh nonce on every
  `/pam/authorize` overwrote the nonce already exported into the other live
  sessions' shells, which then failed at `/pam/bastion-cert` with
  `voucher_mismatch` (symptom: "works only from the most recent login").
  `_mintBastionVoucher` now reuses a still-valid nonce and only extends its
  expiry (never shortens a live voucher), generating a new nonce only when none
  is usable. Voucher minting is gated on the PAM login service
  (`pamAccessBastionVoucherServices`, default `sshd ssh`) so a `sudo`
  authorization check on the bastion has no voucher side effect.

## v0.3.7 - 2026-06-16

Touched plugins bumped to **0.3.7** in lockstep: `pam-access`. Theme: make
the bastion-hop endpoints work under the realistic "one OIDC `client_id` per
project" model, where the device-grant session carries no per-host server
group.

### pam-access

- **Fix — stop gating the bastion endpoints on the caller's `server_group`**.
  `/pam/bastion-token` and `/pam/bastion-cert` previously re-derived the
  caller's group from the access-token session and rejected it unless it was
  in `pamAccessBastionGroups`. With a single OIDC `client_id` shared by every
  host of a project, the device-grant session carries no per-host
  `server_group`, so this always resolved to `default` and rejected every
  legitimate bastion hop. The group check is removed at both endpoints. The
  security property — a bastion may mint credentials only for a user who
  actually connected to it — is carried entirely by the `(bastion_id, user)`
  voucher, which `/pam/authorize` mints only for a host whose resolved
  `server_group` is in `pamAccessBastionGroups`. `/pam/bastion-cert` verifies
  that voucher, so its existence already proves the caller was a legitimate
  bastion at connection time.
- **Change — resolve `/pam/bastion-token`'s informational group
  authoritatively**. The `bastion_group` carried in audit logs, the probe
  response and the signed JWT is now resolved through `pamAccessServerGroups`
  rather than trusted from the request body: when the `client_id`→group
  mapping is configured the mapped group is authoritative (a forged or
  mismatched body group is rejected, as in `/pam/authorize`), so a
  caller-forgeable group is never signed into the JWT. Legacy mode (empty
  mapping) keeps trusting the caller-claimed value. The group remains
  informational for this endpoint — no bastion-group gate is reintroduced.

## v0.3.6 - 2026-06-16

Touched plugins bumped to **0.3.6** in lockstep: `pam-access`. Theme: make
the `/pam/bastion-cert` vouching hop work end-to-end with the `/pam/authorize`
SSH-fingerprint binding, and let deployments behind NAT/PAT or a reverse proxy
opt out of source-address pinning.

### pam-access

- **Fix — accept ephemeral bastion-hop certificates on `/pam/authorize`**.
  Once the backend forwards the ephemeral certificate's public-key
  fingerprint, the `/pam/authorize` SSH-fingerprint binding
  (`_checkSshFingerprint`) rejected the vouched hop as "fingerprint not-found"
  because that fingerprint was never recorded anywhere. `/pam/bastion-cert`
  now registers the issued fingerprint at signing time under a dedicated
  per-fingerprint persistent-session key (`_pamEphCert::<fp>`), consulted
  first by `_checkSshFingerprint`. It is stored outside `_sshCerts` on
  purpose: concurrent hops (`scp host1: host2:`) cannot clobber each other
  (per-key `Session->update` merge) and ssh-ca's SSO cert records are left
  untouched. Entries self-expire with the certificate TTL.
- **Feature — `pamAccessBastionCertPinSourceAddress`**. New boolean option
  (default `0`) gating whether `/pam/bastion-cert` pins the issued certificate
  to the bastion's IP via the `source-address` critical option. Enable it
  whenever there is no NAT/PAT between the bastions and the portal — a free,
  transparent hardening so a leaked certificate is only usable from the
  bastion that requested it. Left off by default so deployments where the
  address LLNG observes differs from the bastion's SSH egress address (reverse
  proxy, multi-homed bastion, NAT/PAT) are not broken. The pin was previously
  unconditional.

## v0.3.5 - 2026-06-15

Touched plugins bumped to **0.3.5** in lockstep: `pam-access`,
`oidc-device-authorization`. Theme: fleet visibility from the Open Bastion
heartbeat (who is connected and what each enrolled machine runs), plus an
authorization fix so device-grant tokens honour the same per-user scope
gate as the authorization-code flow.

### pam-access

- **Feature — connected users from heartbeat**. `/pam/heartbeat` now
  persists the list of users currently connected on a server, reported by
  `ob-heartbeat` in a `sessions` array, into the refresh-token session as
  `_pamSessions` (JSON) plus a `_pamSessionCount`, on the same model as
  `_pamStats` — letting administrators see "who is connected" per machine.
- **Feature — node role from heartbeat**. The `node_role` reported by
  `ob-heartbeat` (`bastion` | `standalone` | `backend`) is stored as
  `_pamNodeRole` next to the existing `_pamVersion`, so the SSO can show
  what each enrolled machine runs.
- **Hardening** — `_pamSessions` is always persisted as a JSON array; a
  non-array `sessions` payload is now coerced to `[]` (with a warning)
  instead of being stored as an inconsistent JSON type while
  `_pamSessionCount` is 0. Covered in `t/07-PamAccess-Heartbeat.t`.

### oidc-device-authorization

- **Fix — resolve granted scope through `getScope` at approval**. The device
  authorization endpoint is pre-auth, so the scope requested there was
  unfiltered and propagated verbatim into the issued tokens, bypassing the
  core `getScope` gate the authorization-code flow applies — neither
  declared-scope filtering (`oidcServiceAllowOnlyDeclaredScopes`) nor the
  per-user dynamic scope rules (`rpScopeRules`) were enforced for
  device-grant tokens. `submitVerification` now resolves the requested scope
  via `getScope` at approval time, where `$req->userData` is the consenting
  user, and stores the resolved scope on the device authorization.

## v0.3.4 - 2026-06-12

Touched plugins bumped to **0.3.4** in lockstep: `pam-access`, `ssh-ca`,
`oidc-device-authorization`. Theme: certificate-based bastion→backend
vouching for Open Bastion (replacing the structurally-broken JWT
`/pam/bastion-token` hop), plus correctness hardening on the device-grant
token endpoint.

### pam-access

- **Feature — `/pam/bastion-cert` certificate vouching**. A new
  server-to-server endpoint signs a short-lived ephemeral SSH user
  certificate for a bastion→backend hop. The bastion proves (1) a valid
  device-grant token for a bastion group and (2) a fresh `(bastion, user)`
  voucher minted by `/pam/authorize` when the user actually connected to it.
  The certificate is pinned to the vouching bastion's IP (`source-address`
  critical option) and encodes the bastion identity in its key-id so a
  backend can enforce its allowed-bastions list. Supersedes the
  structurally-broken JWT `/pam/bastion-token`, now deprecated.
- **Hardening** — `pamAccessBastionVoucherTtl` / `pamAccessBastionCertTtl`
  are validated as positive integers (warn + fall back to the default on
  misconfiguration) instead of feeding garbage to the expiry math and
  `ssh-keygen -V`. Internal voucher-check failures (session backend error,
  corrupted voucher map) now return HTTP 500 `voucher_check_failed` instead
  of 403, so clients and monitoring don't read them as an authorization
  denial. New POD documents the endpoint, the `/pam/authorize` voucher
  fields, the `/pam/bastion-token` deprecation and the `pamAccessBastion*`
  config keys.

### ssh-ca

- **Feature — `_signSshKey` validity / source-address options**. The signing
  helper accepts an optional `$opts` hashref letting callers (pam-access
  bastion-cert vouching) set a sub-minute `validity` (`-V` spec) and a
  `source-address` critical option that pins the issued certificate to a
  given IP/CIDR, enforced natively by sshd. `$opts` is normalized to `{}`
  unless it is a HASH ref.

### oidc-device-authorization

- **Fix — single-use `device_code`**. The device authorization is now
  consumed before the tokens are minted, so a second poll at the normal
  RFC 8628 cadence can no longer exchange the same approved code twice for a
  duplicate token set.
- **Fix — strip `offline_access` from the granted scope**. Mirroring the
  core token endpoint, `offline_access` gates the offline refresh token but
  is no longer advertised in the access token, the response `scope`, the ID
  token or the refresh token (it is a request marker, not a granted scope).

## v0.3.3 - 2026-06-12

Touched plugins bumped to **0.3.3** in lockstep: `oidc-device-authorization`,
`oidc-device-organization`, `pam-access`. Theme: long-lived **offline**
tokens for organization devices (Open Bastion), so an enrolled server keeps
a durable machine identity decoupled from the admin's SSO session.

### oidc-device-authorization

- **Fix — issue offline refresh tokens independently of the online
  `RefreshToken` option**. `_generateTokens` now mirrors the core token
  endpoint: an _offline_ refresh token is gated by the `offline_access`
  scope **plus** `oidcRPMetaDataOptionsAllowOffline`, while an _online_
  refresh token is gated by `oidcRPMetaDataOptionsRefreshToken`. These are
  two independent gates, so `AllowOffline` alone is now enough to mint an
  offline refresh token even when the online `RefreshToken` option is off
  (previously an offline token required the online option to also be set).
  Offline tokens stay standalone (no `user_session_id`), carrying the user
  info — e.g. the synthetic organization identity injected by
  `oidc-device-organization`.

### oidc-device-organization

- **Feature — keep `offline_access` for organization devices**.
  `handleOrganizationDevice` no longer strips `offline_access` from the
  scope, so an organization device receives a long-lived offline refresh
  token (durable machine identity per RFC 8628 / OIDC `offline_access`)
  instead of an online one tied to the admin's SSO session. The classic
  objection — offline refresh re-resolves the synthetic `client_id` in the
  UserDB and fails — does not apply: Open Bastion never uses the core
  `/oauth2/token` refresh grant for these tokens; `pam-access`
  `/pam/heartbeat` mints access tokens directly from the refresh token's
  stored synthetic session data, so the UserDB is never queried at refresh
  time.

### pam-access

- **Fix — scope-check the refresh token in `/pam/heartbeat` (security)**.
  The endpoint mints access tokens and slides the refresh token's lifetime,
  so it now requires the refresh token to actually carry the `pam` /
  `pam:server` scope (`PAM_*` → HTTP 403 `Invalid token scope`). Without
  this gate, any device-code refresh token issued for another RP/scope could
  call `/pam/heartbeat` to obtain access tokens and keep itself alive
  indefinitely. Same scope gate as `/pam/authorize` and
  `/pam/bastion-token`.
- **Feature — `/pam/heartbeat` mints a fresh access token and renews the
  offline session**. The endpoint now resolves the RP from the refresh
  token's `_clientConfKey` (falling back to a `client_id` lookup), mints a
  fresh access token from the stored synthetic session data via
  `newAccessToken` (returned as `access_token` + `expires_in`), and slides
  the refresh-token session's `_utime` forward by the RP's
  `OfflineSessionExpiration`. A live server that keeps beating thus never
  ages out, while a server that stops beating is purged after that grace
  window. Minting locally (rather than via the core refresh grant) keeps the
  server identity self-contained and avoids the UserDB re-resolution that
  fails for synthetic organization identities.

## v0.3.2 - 2026-06-12

Touched plugin bumped to **0.3.2**: `pam-access`.

### pam-access

- **Fix — probe mode for `/pam/bastion-token`**. When the request body
  carries `"probe": true`, the endpoint returns the `bastion_id`
  (derived from the token's `client_id`) directly, skipping the per-user
  `_pamSeen` recency gate and without minting a usable JWT. The earlier
  checks (valid device-grant token, scope, and group membership in
  `pamAccessBastionGroups`) still apply, so only a legitimate bastion can
  learn its own id. Lets `ob-bastion-id` self-identify — it previously
  got HTTP 403 because its synthetic probe user can never satisfy the
  recency gate.

## v0.3.1 - 2026-06-06

- **store** - Add fix for LLNG 2.23.0

## v0.3.0 - 2026-05-26

Touched plugin bumped to **0.3.0**: `krb-provisioning` (new).

### krb-provisioning (new)

- **Feature — on-the-fly Kerberos provisioning from SSO logins**: at each
  real (password-based) login, (re)sets the user's Kerberos key equal to the
  password just validated by the SSO, by talking to `kadmind` through
  `Authen::Krb5::Admin` (libkadm5). Lets a dedicated MIT KDC issue tickets for
  users whose identities live in a separate general LDAP directory the KDC
  cannot delegate to. Creates the principal on first login (`addprinc`) and
  resets its key on every subsequent login (`cpw`) to absorb password drift.

## v0.2.2 - 2026-05-20

Touched plugin bumped to **0.2.2**: `pam-access`.

### pam-access

- **Fix** — new `pamAccessChoice` option. When LemonLDAP::NG is
  configured with Choice authentication (`Auth = Choice`,
  `UserDB = Choice`), set this to the name of an `authChoiceModules`
  entry (e.g. `1_LDAP`) so that the server-to-server endpoints
  `/pam/authorize`, `/pam/userinfo` and `/pam/bastion-token` can route
  their `getUser` step through `Lib::Choice`. Leave empty when Choice
  auth is not used — behavior is unchanged.

## v0.2.1 - 2026-05-13

Touched plugins bumped to **0.2.1** in lockstep: `oidc-grant-management`
(new), `oidc-rar`, `oidc-resource-indicators`, `oidc-ciba`.

### oidc-grant-management (new)

- **Feature - FAPI Grant Management API** (OIDC Provider side):
  grants as durable first-class records, `grant_management_action`
  parameter (`create` / `update` / `replace`) on `/oauth2/authorize`,
  `grant_id` claim on token responses, REST endpoint at
  `/oauth2/grants/{grant_id}` (GET to query, DELETE to revoke; token
  cascade on revoke is best-effort in v1).

### oidc-rar

- **Refactor** - encode per-type rules as a JSON scalar option
  (`oidcRPMetaDataOptionsRARRules`) instead of a hash-of-X ctree
  container — aligns with the manager-builder constraint (PR #25).
- **Fix** - use array form for multiple ctree injections; the previous
  `target` field on the second entry was silently dropped, generating
  spurious `*Keys` ctrees (with `oidc-ciba`).

### oidc-resource-indicators

- **Fix** - encode RS scopes / rules as JSON scalars

### oidc-ciba

- **Fix** - use array form for multiple ctree injections (`target`
  field on second ctree entry was dropped, generating a spurious
  `_oidcRPMetaDataNodeCibaKeys` ctree).

### crowdsec-filters

- **New filter `llng/http-probing`** — catches scanners abusing
  OAuth2 / SSO redirect parameters (`state`, `redirect_uri`, `return`,
  `next`, `callback`, …) to probe for sensitive paths
  (`phpinfo.php`, `.env`, `wp-admin`, …). Threshold 2 hits / 30 s.

### LLNG 2.0.11 backport

- Direct link to Debian sources in `v2.0.11/README.md`.

### Tooling & docs

- **`llng-build-manager-files`** — reject plugin hash-of-X containers
  as ctree leaves; emit a clear error pointing at the bad node so
  refactors like `oidc-rar` / `oidc-resource-indicators` above can't
  regress silently (PR #24).
- **CI** — new `validate-overrides` job runs `llng-build-manager-files`
  on every plugin to catch malformed `manager-overrides/*.json` before
  release; pulls in `Regexp::Common` + `Mouse` test deps.
- **Docs** — new `OIDC.md` narrative (high-level OIDC plugin tour),
  `SPECIFICATIONS.md` brought up to date, `oidc-grant-management`
  README expanded.

## v0.2.0 - 2026-05-01

Touched plugins bumped to **0.2.0** in lockstep: `oidc-rar` (new),
`oidc-resource-indicators` (new), `oidc-acr-claims` (new), `oidc-par`,
`twake`.

### oidc-rar (new)

- **Feature - RFC 9396 Rich Authorization Requests** (OIDC Provider
  side): `authorization_details` parsing on `/oauth2/authorize`,
  persistence through code/refresh/AT sessions, echo in token
  responses + JWT AT, introspection, discovery advertisement.

### oidc-resource-indicators (new)

- **Feature - RFC 8707 Resource Indicators** (OIDC Provider side):
  `resource` parameter on `/oauth2/authorize` and `/oauth2/token`
  (`client_credentials` + refresh), per-RS scope rules
  (`oidcRPMetaDataOptionsRIScopeRules`), token binding (JWT `aud`,
  introspection, refresh).

### oidc-acr-claims (new)

- **Feature - RFC 9470 AS-side claims**: emit `acr` + `auth_time` on
  the JWT access token (mirrors core's ID-token mapping —
  `oidcServiceMetaDataAuthnContext` then `loa-<level>`). Per-RP opt-in
  via `oidcRPMetaDataOptionsAcrClaims`.

### oidc-par

- **Feature - forward `authorization_details` (RFC 9396)** through
  PAR sessions: added to the parameter allowlists in `pushAuthRequest`
  and `resolvePushedRequest`. Was previously dropped between
  `/oauth2/par` and `/oauth2/authorize`.

### twake

- **Refactor - dedicated bool activation flag**: replace the
  `keyTextContainer` condition (`twakeWellKnown`) with a real `bool`
  attribute (`twakeWellKnownActivation`); manager tree reorganised
  under a `wellKnown` node.

### crowdsec-filters

- Refresh trendy CVE URIs (snapshot 2026-04-27).

### Tooling & docs

- `llng-build-manager-files`: prefer `terser` over `uglifyjs` when
  both are available (PR #17).
- READMEs: clarify that `lemonldap-ng-store` is bundled with
  LLNG ≥ 2.24.0; LLNG 2.23.x users need the
  `linagora-lemonldap-ng-store` backport (built from `store/`).
- `plugin.json`: `author` field normalised.

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
