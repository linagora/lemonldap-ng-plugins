# SSH CA - SSH Certificate Authority

This plugin provides SSH certificate signing functionality for LemonLDAP::NG.
Users can sign their SSH public keys to obtain short-lived certificates for
passwordless authentication on servers that trust the CA.

## Features

- **Certificate signing** with configurable validity and principals.
- **Mandatory key labels** for human-friendly identification (e.g.
  `laptop-pro`), enforced unique per user among active certificates.
- **Automatic dedup on re-signature**: signing the same SSH public key
  twice replaces the previous record in the user's session and publishes
  the superseded serial in the KRL — a user has a single active record
  per fingerprint at all times.
- **User self-revocation** via `POST /ssh/myrevoke` and a per-row
  "Revoke" button in the "My Certificates" table.
- **Certificate listing** for users (their own) and admins (all users).
- **Certificate revocation** with KRL (Key Revocation List) management.
- **SSH SHA256 fingerprint** computed and stored with each cert, surfaced
  in the responses — the `pam-access` plugin uses it to bind PAM tokens
  to a specific SSH key.
- **Admin interface** for searching and revoking certificates.
- **Audit logging** of all signing and revocation operations.

## Requirements

- LemonLDAP::NG >= 2.23.0
- `ssh-keygen` available on the system
- `Crypt::PK::Ed25519` (for Ed25519 CA keys) or `Crypt::PK::RSA` (for RSA CA keys)

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```bash
sudo lemonldap-ng-store install ssh-ca
```

Manually: copy `lib/` into your Perl `@INC` path, copy `portal-templates/`
and `portal-static/` into the portal directories, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-overrides.d/`, add `::Plugins::SSHCA` to
`customPlugins`, and run `llng-build-manager-files`.

## Configuration

In the Manager under **General Parameters** > **Plugins** > **SSH CA**:

| Parameter               | Description                                                               | Default                                  |
| ----------------------- | ------------------------------------------------------------------------- | ---------------------------------------- |
| `sshCaKeyRef`           | Reference to the SSH CA key in LLNG keys store                            | _(required)_                             |
| `sshCaKrlPath`          | Path to the KRL file on disk                                              | `/var/lib/lemonldap-ng/ssh/revoked_keys` |
| `sshCaCertMaxValidity`  | Maximum certificate validity in days                                      | `365`                                    |
| `sshCaPrincipalSources` | Session attributes to use as principals (space-separated `$var` template) | `$uid`                                   |

### CA key setup

The CA key must be configured in the LLNG keys store (Manager > Keys). Both
Ed25519 and RSA keys are supported. The plugin converts PEM keys to OpenSSH
format internally.

### Principal sources

Principals are always derived from the authenticated user's session, never
from the request. The `sshCaPrincipalSources` parameter is a template string
where `$varname` references are replaced with session attribute values.

Examples:

- `$uid` → principal is the user's uid (e.g. `john`)
- `$uid $mail` → two principals: uid and email (e.g. `john`, `john@example.com`)

## Endpoints

### Public endpoints (no authentication)

| Method | Path           | Description                                                                                                        |
| ------ | -------------- | ------------------------------------------------------------------------------------------------------------------ |
| GET    | `/ssh/ca`      | Returns the CA public key in SSH format. Servers use this to configure `TrustedUserCAKeys`.                        |
| GET    | `/ssh/revoked` | Returns the binary KRL file. Servers use this to configure `RevokedKeys`. Returns empty body if no KRL exists yet. |

### User endpoints (authentication required)

| Method | Path             | Description                                                                     |
| ------ | ---------------- | ------------------------------------------------------------------------------- |
| GET    | `/ssh`           | User interface for signing SSH keys                                             |
| POST   | `/ssh/sign`      | Sign a user's SSH public key (requires a unique `label` among active certs)     |
| GET    | `/ssh/mycerts`   | List the current user's certificates (JSON)                                     |
| POST   | `/ssh/myrevoke`  | Self-revoke one of the caller's own certificates; immediately added to the KRL  |

### Admin endpoints (authentication + access control required)

| Method | Path          | Description                                             |
| ------ | ------------- | ------------------------------------------------------- |
| GET    | `/ssh/admin`  | Admin interface for searching and revoking certificates |
| GET    | `/ssh/certs`  | Search all certificates across all users (JSON)         |
| POST   | `/ssh/revoke` | Revoke a certificate by session ID and serial           |

**Important:** Admin endpoints have no built-in access control beyond
authentication. You must configure `locationRules` on the portal vhost to
restrict access. Example:

```perl
# In LLNG Manager > Virtual Hosts > portal vhost > Rules
^/ssh/admin    => $uid eq 'admin' or inGroup('ssh-admins')
^/ssh/certs    => $uid eq 'admin' or inGroup('ssh-admins')
^/ssh/revoke   => $uid eq 'admin' or inGroup('ssh-admins')
```

## API details

### POST /ssh/sign

Request (JSON):

```json
{
  "public_key": "ssh-ed25519 AAAA... user@host",
  "validity_days": 30,
  "label": "laptop-pro"
}
```

Response (JSON):

```json
{
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "serial": 3,
  "key_id": "john@llng-1713300000-000003",
  "principals": ["john"],
  "valid_until": "2026-05-16T12:00:00Z",
  "label": "laptop-pro",
  "fingerprint": "SHA256:CfGkzWrzpeKEsYPdBMDjEjoN1n/o4YzuM8StGuMQMcs"
}
```

- `label` is **mandatory**. It must be unique across the user's active
  (non-revoked, non-expired) certificates. Re-using a label on a different
  key yields HTTP 409. If omitted, the plugin falls back to the SSH public
  key's comment (third token) for back-compat; if that is also empty the
  request is rejected with 400.
- `validity_days` is clamped to `sshCaCertMaxValidity`.
- Principals are derived from the session; any `principals` field in the
  request is ignored (and logged as a warning).
- `fingerprint` is the SHA256 of the signed key, stored with the cert and
  used by the `pam-access` plugin to bind PAM tokens to a specific key.

**Re-signing the same SSH public key** (same fingerprint) replaces the
previous record in the user's persistent session and revokes the
superseded serial in the KRL. The `label` may change on re-signature. The
KRL retains all revoked serials regardless.

### POST /ssh/myrevoke

Request (JSON):

```json
{ "serial": "3" }
```

Marks the cert as `revoked` in the caller's persistent session (keeping
it visible in `/ssh/mycerts`) and publishes the serial in the KRL.

Returns HTTP 400 if already revoked, HTTP 404 if the serial is not in the
caller's own certs.

### GET /ssh/mycerts

Response (JSON):

```json
{
  "certificates": [
    {
      "serial": 3,
      "key_id": "john@llng-1713300000-000003",
      "label": "laptop-pro",
      "fingerprint": "SHA256:CfGkzWrzpeKEsYPdBMDjEjoN1n/o4YzuM8StGuMQMcs",
      "principals": "john",
      "issued_at": 1713300000,
      "expires_at": 1715892000,
      "status": "active"
    }
  ]
}
```

Status is computed dynamically: `active`, `expired` (past `expires_at`), or
`revoked` (has `revoked_at`). Entries are sorted newest-first.

### GET /ssh/certs

Query parameters: `user`, `serial`, `key_id`, `status`, `limit` (max 1000),
`offset`.

Response includes all fields from `/ssh/mycerts` (including `label` and
`fingerprint`) plus: `session_id`, `user`, `revoked_at`, `revoked_by`,
`revoke_reason`.

### POST /ssh/revoke

Request (JSON):

```json
{
  "session_id": "persistent-session-id",
  "serial": "1",
  "reason": "Key compromised"
}
```

This does two things:

1. Marks the certificate as revoked in the user's persistent session
2. Updates the KRL file on disk via `ssh-keygen -k [-u] -s ca.pub -f <krlPath>`

## KRL (Key Revocation List)

The KRL is a binary file managed by `ssh-keygen`. It is updated each time a
certificate is revoked via `/ssh/revoke`. The first revocation creates the
KRL; subsequent revocations append to it (`-u` flag).

Servers should periodically fetch the KRL from `/ssh/revoked` and configure:

```
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/ca.pub
RevokedKeys /etc/ssh/revoked_keys
```

A cron job or systemd timer can keep the KRL up to date:

```bash
curl -sf https://auth.example.com/ssh/revoked -o /etc/ssh/revoked_keys
```

## Storage

Certificates are stored in each user's **persistent session** under the
`_sshCerts` key (JSON array). This means certificates survive across SSO
sessions. The admin search endpoint (`/ssh/certs`) scans all persistent
sessions to find certificates.

Serial numbers are stateless: they are derived from the current
microsecond-precision wall clock plus a small random tail, so two portals
can issue in parallel without coordination and without collisions.

## Multi-portal deployments (issue #9)

If you run more than one portal node behind a load balancer, each node
keeps its own local KRL file. The plugin keeps those KRLs in sync via
LLNG's message broker (available since LLNG 2.20.0): every revocation
is both written to the local KRL and published as a `sshCaRevoke` event
on the `eventQueueName` channel. Sibling nodes subscribe to that event
at plugin init and apply the same revocation to their local KRL,
typically within 5 seconds (the handler's event poll interval).

**Requirement**: configure a real message broker. The default
`::NoBroker` only dispatches in-process, so revocations would not
propagate between portals. Supported backends:

```perl
# /etc/lemonldap-ng/lemonldap-ng.ini (each portal node)
messageBroker        = ::Redis
messageBrokerOptions = { "server": "redis.example.com:6379" }
# or ::MQTT, ::Pg (PostgreSQL LISTEN/NOTIFY)
```

### Drift recovery: `sshca-rebuild-krl` cron

The broker is the fast path, not the source of truth: it is a
non-durable pub/sub, so a node that is down during a revocation misses
the event. Schedule the `sshca-rebuild-krl` script (shipped in
`scripts/`) from cron on every portal node to reconcile:

```
# /etc/cron.d/lemonldap-ng-sshca
*/5 * * * * www-data [ -x /usr/share/lemonldap-ng/bin/sshca-rebuild-krl ] && /usr/share/lemonldap-ng/bin/sshca-rebuild-krl
```

The script scans the persistent sessions (which are shared across
portals via the session backend), collects every certificate with a
`revoked_at` timestamp, and rewrites the local KRL with
`ssh-keygen -k`. Safe to run on a single-node setup too — it just
becomes a no-op when nothing is out of sync.

## Server-side configuration

To configure an SSH server to trust certificates signed by this CA:

```bash
# Fetch the CA public key
curl -sf https://auth.example.com/ssh/ca -o /etc/ssh/ca.pub

# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/ca.pub
RevokedKeys /etc/ssh/revoked_keys

# Optionally restrict principals
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

## See Also

- [SSH CA documentation](https://lemonldap-ng.org/documentation/latest/sshca)
- [OpenSSH certificates](https://man.openbsd.org/ssh-keygen#CERTIFICATES)
- [PAM Access plugin](../pam-access/README.md) — consumes the SHA256
  fingerprint exposed here to bind PAM tokens to a specific SSH key.
