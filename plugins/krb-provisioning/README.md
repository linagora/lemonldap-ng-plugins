# Kerberos provisioning - on-the-fly KDC principal sync

This plugin provisions and resynchronizes a user's Kerberos principal **at
each real login**, using the cleartext password that LemonLDAP::NG already
holds while validating the user against the general directory.

## Why

A dedicated MIT KDC keeps its principals in a separate, autonomous OpenLDAP
base. Kerberos cannot delegate authentication to the general identity
directory at `kinit` time: the KDC needs the **key derived from the password**
already present in its base. That key can only be built when someone sees the
cleartext password — and the SSO login is exactly that moment.

On every password-based login, this plugin sets (or resets) the user's
Kerberos key equal to their current password, so they can then obtain tickets
(`kinit` / Kerberos SSO) against the KDC. It does **not** manage the KDC, the
realm, the `krbContainer`, or deprovisioning — those belong to the `pure-kdc`
project and a separate reconciliation job.

## Features

- **`betweenAuthAndData` hook** — runs right after the password is validated
  and **before** the second-factor gate, while the cleartext password is still
  on the request. This is deliberately _not_ `endAuth`: see [MFA](#mfa) below.
- **Idempotent** — creates the principal on first login (`addprinc`), and
  resets its key on every subsequent login (`cpw`) to absorb password drift
  in the general directory.
- **Strictly non-blocking** — any kadmind error is logged and swallowed; the
  SSO authentication always succeeds.
- **Silent no-op without a cleartext password** — cookie SSO, SAML/OIDC
  federation, SPNEGO: nothing to provision, no kadmin call.
- **Password never leaks** — it is used in memory only, never logged, and
  never passed as a command-line argument (no `-pw`, cf. `/proc/<pid>/cmdline`).
- **Two backends** — [`Authen::Krb5::Admin`](https://metacpan.org/pod/Authen::Krb5::Admin)
  (in-memory `libkadm5` bindings) when available, otherwise a fallback that
  shells to `kadmin` and feeds the password on **stdin**, with a short timeout.

## Requirements

- LemonLDAP::NG >= 2.23.0
- A reachable `kadmind`, a service principal (e.g. `lemonldap/admin@REALM`)
  and its keytab, readable only by the portal process.
- `Authen::Krb5::Admin` _(recommended)_, or the `kadmin` client in `PATH`.
- The KDC's `kadm5.acl` must grant the service principal **only** `add`,
  `changepw` and `modify` (no `delete`, no `*`).

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.24.0)_ or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```bash
sudo lemonldap-ng-store install krb-provisioning
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-overrides.d/`, add `::Plugins::KrbProvisioning`
to `customPlugins`, and run `llng-build-manager-files`.

## Configuration

In the Manager under **General Parameters** > **Plugins** > **Kerberos
provisioning**:

| Parameter                   | Description                                                  | Default      |
| --------------------------- | ------------------------------------------------------------ | ------------ |
| `krbProvisioningActivation` | Enable the plugin                                            | `0`          |
| `krbRealm`                  | Kerberos realm of the provisioned principals                 | _(required)_ |
| `krbAdminServer`            | `kadmind` server as `host[:port]`                            | _(required)_ |
| `krbServicePrincipal`       | Service principal used to authenticate to kadmind            | _(required)_ |
| `krbKeytab`                 | Path to the service principal's keytab                       | _(required)_ |
| `krbPrincipalAttribute`     | Session attribute holding the principal name (empty = login) | _(login)_    |
| `krbPrincipalFormat`        | `sprintf` template applied to `(login, realm)`               | `%s@%s`      |
| `krbDefaultPolicy`          | Kerberos policy applied to created principals (optional)     | _(empty)_    |
| `krbConnectTimeout`         | kadmind connection/command timeout in seconds                | `3`          |

The mapping is `principal = sprintf(krbPrincipalFormat, login, krbRealm)`,
where `login` is `krbPrincipalAttribute` from the session, or the login
(`REMOTE_USER`) when that parameter is empty. Logins that are empty or contain
characters invalid in a principal component (whitespace, `@`, `/`, NUL) are
ignored.

> **Note:** do not enable `storePassword` for this plugin. The password is only
> needed transiently, in memory, for the duration of the kadmin call.

## MFA

With multi-factor authentication, the OTP is submitted in a **second** request
that carries no password and only re-runs `buildCookie` + `endAuth`. Hooking
`endAuth` would therefore see an empty `$req->data->{password}` and never
provision MFA users. The plugin hooks `betweenAuthAndData` instead, which runs
on the **credentials** request, right after the password is validated and
before the second-factor gate — so provisioning happens exactly once, with the
password, regardless of whether a second factor follows.

Consequence: the Kerberos key is set as soon as the password is validated,
even if the user later fails or abandons the second factor. This is consistent
with Kerberos itself, which is single-factor by design and cannot enforce the
SSO's OTP at `kinit` time — the password was genuinely validated against the
directory, which is the guarantee that matters for setting the key.

Because the principal is resolved this early, `krbPrincipalAttribute` must name
an attribute already populated by the UserDB at `getUser` time. When empty (the
default) or when the attribute is not yet available, the login (`REMOTE_USER`)
is used.

## Acceptance criteria

1. First login of a known user → principal `<uid>@REALM` created; `kinit`
   succeeds with that password.
2. Repeated login → no error, `kinit` keeps working (idempotent `cpw`).
3. Password changed in the general directory, then new SSO login → `kinit`
   succeeds with the **new** password (resync).
4. `kadmind` down during a login → SSO **still succeeds** (failure logged,
   non-blocking).
5. Cookie SSO (no re-entry) → no kadmin call.
6. The password appears in no log and in no `/proc` entry.

## Testing

```bash
./mcp/cli.js test krb-provisioning
```

The test suite mocks the kadmind backend (no real KDC needed) and covers the
mapping, the no-op paths, the non-blocking guarantee, the
password-never-logged / never-in-argv constraints, and an **MFA** scenario
(external 2F) proving the principal is provisioned on the credentials request
and not lost across the OTP step.
