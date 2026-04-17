# vault-conf-backend — OpenBAO / Vault KV v2 configuration backend

This plugin stores LemonLDAP::NG configuration in OpenBAO or HashiCorp Vault using the KV v2 secret engine.
It provides a drop-in replacement for the file-based backend with automatic locking and concurrency safety for multi-server deployments.

Requires **LLNG >= 2.0.0** and Vault / OpenBAO with **KV v2 engine** (KV v1 is not supported).

## Installation

### Via the LLNG store

```bash
lemonldap-ng-store install vault-conf-backend
```

### Manual installation

Copy the Perl module into LemonLDAP::NG's library path:

```bash
cp lib/Lemonldap/NG/Common/Conf/Backends/OpenBAO.pm \
   /usr/share/perl5/Lemonldap/NG/Common/Conf/Backends/
```

### Via Debian package

If your system uses LLNG Debian packages:

```bash
sudo apt-get install lemonldap-ng-plugin-vault-conf-backend
```

## Configuration

Configure the backend in `lemonldap-ng.ini` under the `[configuration]` section.

### Minimal example (static token)

```ini
[all]
confTimeout = 30

[configuration]
type    = OpenBAO
baseUrl = https://bao.internal:8200/v1
token   = %SERVERENV:OPENBAO_TOKEN%
useServerEnv = 1
```

### Full example with all options

```ini
[all]
confTimeout = 30

[configuration]
type         = OpenBAO
baseUrl      = https://bao.internal:8200/v1
mount        = secret
path         = lmConf
lockTtl      = 60
useServerEnv = 1

; --- Authentication: static token ---
token = %SERVERENV:OPENBAO_TOKEN%

; OR authentication: AppRole (mutually exclusive with token)
; roleId       = %SERVERENV:OPENBAO_ROLE_ID%
; secretId     = %SERVERENV:OPENBAO_SECRET_ID%
; approleMount = approle

; --- Optional: OpenBAO Enterprise namespace ---
namespace = team-sso

; --- Optional: TLS / LWP configuration ---
lwpOpts = { timeout => 4 }
lwpSslOpts = { SSL_ca_file => /etc/ssl/bao-ca.pem }
```

### Parameter reference

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `type` | string | — | Must be `OpenBAO` |
| `baseUrl` | string | — | Full Vault/OpenBAO API URL **including** `/v1` or `/v2` API prefix. Example: `https://vault.example.com:8200/v1` |
| `mount` | string | `secret` | KV v2 mount point name |
| `path` | string | `lmConf` | Secret path under the mount (configurations stored as `<mount>/data/<path>/lmConf-<cfgNum>`) |
| `lockTtl` | integer | `60` | Lock secret time-to-live in seconds. Must be > 0 |
| `useServerEnv` | integer | — | Set to `1` to enable `%SERVERENV:VAR%` placeholder substitution (required for injecting secrets) |
| `token` | string | — | Static authentication token. Use `%SERVERENV:OPENBAO_TOKEN%` with `useServerEnv = 1` |
| `roleId` | string | — | AppRole role ID (requires `secretId`; mutually exclusive with `token`) |
| `secretId` | string | — | AppRole secret ID (requires `roleId`; mutually exclusive with `token`) |
| `approleMount` | string | `approle` | AppRole auth mount path (only used if `roleId` is set) |
| `namespace` | string | — | OpenBAO Enterprise namespace name. Passed as `X-Vault-Namespace` header if set |
| `lwpOpts` | hash | — | Options passed to `LWP::UserAgent::new()`. Example: `{ timeout => 4, ssl_opts => {...} }` |
| `lwpSslOpts` | hash | — | TLS options passed to `LWP::UserAgent`. Example: `{ SSL_ca_file => /path/to/ca.pem, verify_hostname => 0 }` |

### Environment variable injection

With `useServerEnv = 1`, LLNG replaces `%SERVERENV:VAR%` placeholders at startup. This allows injecting secrets without storing them in the INI file:

```ini
token = %SERVERENV:OPENBAO_TOKEN%
```

Set the environment variable before starting LLNG:

```bash
export OPENBAO_TOKEN="hvs.CAESIKx..."
lemonldap-ng-portal
```

### Authentication modes

Choose exactly one:

**Static token** — simplest, suitable for static credentials:

```ini
token = %SERVERENV:OPENBAO_TOKEN%
```

**AppRole** — recommended for dynamic credentials and automated systems:

```ini
roleId       = %SERVERENV:OPENBAO_ROLE_ID%
secretId     = %SERVERENV:OPENBAO_SECRET_ID%
approleMount = approle
```

Both modes require `useServerEnv = 1` if using environment variable placeholders.

### TLS configuration

Use `lwpSslOpts` to configure certificate verification and custom CAs:

```ini
lwpSslOpts = { SSL_ca_file => /etc/ssl/certs/bao-ca.pem }
```

To disable verification (development only):

```ini
lwpSslOpts = { verify_hostname => 0, SSL_verify_mode => 0 }
```

The `lwpOpts` parameter configures general LWP behavior:

```ini
lwpOpts = { timeout => 5 }
```

## Required OpenBAO / Vault policy

Grant the application's authentication principal (token or AppRole) these capabilities:

```hcl
path "secret/data/lmConf/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/metadata/lmConf/*" {
  capabilities = ["list", "read", "delete"]
}

path "auth/approle/login" {
  capabilities = ["update"]
}
```

The first two paths cover configuration storage and locking.
The third path is only needed if using AppRole authentication.

## Kubernetes / Helm deployment

Use a Helm `values.yaml` to inject the token via an environment variable:

```yaml
portal:
  env:
    - name: OPENBAO_TOKEN
      valueFrom:
        secretKeyRef:
          name: openbao-secret
          key: token
```

Then reference it in `lemonldap-ng.ini` (in a ConfigMap):

```ini
[configuration]
type         = OpenBAO
baseUrl      = https://bao.vault.svc.cluster.local:8200/v1
token        = %SERVERENV:OPENBAO_TOKEN%
useServerEnv = 1
```

Alternatively, use AppRole with separate role ID and secret ID stored in Kubernetes secrets:

```yaml
portal:
  env:
    - name: OPENBAO_ROLE_ID
      valueFrom:
        secretKeyRef:
          name: openbao-approle
          key: role-id
    - name: OPENBAO_SECRET_ID
      valueFrom:
        secretKeyRef:
          name: openbao-approle
          key: secret-id
```

## Running the test suite

Install test-only dependencies:

```bash
apt-get install libjson-perl liblwp-useragent-perl libtry-tiny-perl
cpan Test::More Test::MockModule Test::MockObject HTTP::Response
```

Or with cpanminus:

```bash
cpanm Test::More Test::MockModule Test::MockObject HTTP::Response
```

Run the full test suite:

```bash
cd plugins/vault-conf-backend
prove -v -I lib -I t/lib t/*.t
```

Individual test files:
- `00-load.t` — module loads correctly
- `10-prereq.t` — configuration validation
- `20-auth-token.t` — static token authentication
- `21-auth-approle.t` — AppRole authentication and token renewal
- `30-store-load.t` — configuration storage and retrieval
- `40-lock-cas.t` — distributed locking with CAS semantics
- `50-namespace-tls.t` — namespace header and TLS options

## Troubleshooting

### 403 Forbidden

**Cause:** The token / AppRole principal lacks permissions.

**Solution:** Verify the policy is attached to the token/role and includes all three paths in §Required OpenBAO / Vault policy.

### 404 Not Found

**Cause:** The mount name or path does not exist, or baseUrl is incorrect.

**Solution:**
- Verify `mount` matches the KV v2 engine mount name: `vault secrets list`
- Check that `baseUrl` points to the correct Vault/OpenBAO server and includes the `/v1` prefix
- Ensure the path under the mount exists (it will be created on first config save)

### Lock stuck after Manager crash

**Cause:** A lock secret remains after the Manager process dies.

**Solution:** Locks have a TTL of 60 seconds (configurable via `lockTtl`). Either:
- Wait for the lock to expire
- Manually purge it:
  ```bash
  lemonldap-ng-cli conf purge-lock
  ```

### 400 Bad Request with "invalid path for this backend"

**Cause:** `baseUrl` is missing the `/v1` prefix.

**Solution:** Ensure `baseUrl` ends with `/v1` (or `/v2` if using Vault API v2):
```ini
baseUrl = https://vault.example.com:8200/v1
```

### Configuration save timeout or hangs

**Cause:** `confTimeout` is too low for the round-trip latency.

**Solution:** Increase `confTimeout` in the `[all]` section:
```ini
[all]
confTimeout = 30
```

The default is 10 seconds; AppRole logins + TLS negotiation can exceed this.

### TLS certificate verification failures

**Cause:** Self-signed certificates or missing CA bundle.

**Solution:**
- Point to your CA bundle:
  ```ini
  lwpSslOpts = { SSL_ca_file => /etc/ssl/certs/ca-bundle.crt }
  ```
- Or disable verification (development only):
  ```ini
  lwpSslOpts = { verify_hostname => 0, SSL_verify_mode => 0 }
  ```

### Clock skew between servers

**Cause:** The portal server's clock is significantly ahead/behind the Vault server.

**Solution:** Sync system time using NTP:
```bash
ntpdate -u time.nist.gov
```

The lock TTL is computed using the portal's wall clock, so skew can cause premature expiry or false "still locked" errors.

## Known limitations

- **KV v1 not supported** — Only Vault/OpenBAO KV v2 engine is supported. KV v1 compatibility may be added in a future release.
- **No Kubernetes service account auth (v1)** — Only static tokens and AppRole are supported. Kubernetes auth backend support may be added in a future release.
- **No KV v2 versioning** — Configurations are stored as individual secrets per `cfgNum`, not leveraging KV v2's native versioning feature.

## License

This plugin is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0).
