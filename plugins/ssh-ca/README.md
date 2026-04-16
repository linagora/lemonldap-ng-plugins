# SSH CA - SSH Certificate Authority

This plugin provides SSH certificate signing functionality for LemonLDAP::NG.
Users can sign their SSH public keys to obtain short-lived certificates for
passwordless authentication on servers that trust the CA.

## Features

- **Certificate signing** with configurable validity and principals
- **Certificate listing** for users (my certificates) and admins (all certificates)
- **Certificate revocation** with KRL (Key Revocation List) management
- **User portal interface** for self-service key signing
- **Admin interface** for searching and revoking certificates
- **Audit logging** of all signing and revocation operations

## Requirements

- LemonLDAP::NG >= 2.23.0
- `ssh-keygen` available on the system
- `Crypt::PK::Ed25519` (for Ed25519 CA keys) or `Crypt::PK::RSA` (for RSA CA keys)

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```bash
sudo lemonldap-ng-store install ssh-ca --activate
```

Manually: copy `lib/` into your Perl `@INC` path, copy `portal-templates/`
and `portal-static/` into the portal directories, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-overrides.d/`, add `::Plugins::SSHCA` to
`customPlugins`, and run `llng-build-manager-files`.

## Configuration

In the Manager under **General Parameters** > **Plugins** > **SSH CA**:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `sshCaKeyRef` | Reference to the SSH CA key in LLNG keys store | _(required)_ |
| `sshCaKrlPath` | Path to the KRL file on disk | `/var/lib/lemonldap-ng/ssh/revoked_keys` |
| `sshCaSerialPath` | Path to the serial counter file | `/var/lib/lemonldap-ng/ssh/serial` |
| `sshCaCertMaxValidity` | Maximum certificate validity in days | `365` |
| `sshCaPrincipalSources` | Session attributes to use as principals (space-separated `$var` template) | `$uid` |

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

| Method | Path | Description |
|--------|------|-------------|
| GET | `/ssh/ca` | Returns the CA public key in SSH format. Servers use this to configure `TrustedUserCAKeys`. |
| GET | `/ssh/revoked` | Returns the binary KRL file. Servers use this to configure `RevokedKeys`. Returns empty body if no KRL exists yet. |

### User endpoints (authentication required)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/ssh` | User interface for signing SSH keys |
| POST | `/ssh/sign` | Sign a user's SSH public key |
| GET | `/ssh/mycerts` | List the current user's certificates (JSON) |

### Admin endpoints (authentication + access control required)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/ssh/admin` | Admin interface for searching and revoking certificates |
| GET | `/ssh/certs` | Search all certificates across all users (JSON) |
| POST | `/ssh/revoke` | Revoke a certificate by session ID and serial |

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
  "validity_days": 30
}
```

Response (JSON):

```json
{
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "serial": 1,
  "key_id": "john@llng-1713300000-000001",
  "principals": ["john"],
  "valid_until": "2026-05-16T12:00:00Z"
}
```

The `validity_days` is clamped to `sshCaCertMaxValidity`. Principals are
derived from the session, any `principals` field in the request is ignored
(and logged as a warning).

### GET /ssh/mycerts

Response (JSON):

```json
{
  "certificates": [
    {
      "serial": 1,
      "key_id": "john@llng-1713300000-000001",
      "principals": "john",
      "issued_at": 1713300000,
      "expires_at": 1715892000,
      "status": "active"
    }
  ]
}
```

Status is computed dynamically: `active`, `expired` (past `expires_at`), or
`revoked` (has `revoked_at`).

### GET /ssh/certs

Query parameters: `user`, `serial`, `key_id`, `status`, `limit` (max 1000),
`offset`.

Response includes all fields from `/ssh/mycerts` plus: `session_id`, `user`,
`revoked_at`, `revoked_by`, `revoke_reason`.

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

Serial numbers are stored in a plain text file (`sshCaSerialPath`) with
file locking (`flock`) for atomic increments.

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
