# SSH CA - SSH Certificate Authority

This plugin provides SSH certificate signing functionality for LemonLDAP::NG.

## Features

- **Public CA key endpoint** (`/ssh/ca`): serves the CA public key (no auth)
- **Key Revocation List** (`/ssh/revoked`): serves the KRL (no auth)
- **Certificate signing** (`/ssh/sign`): signs user SSH public keys (auth required)
- **Certificate listing** (`/ssh/certs`): search issued certificates (admin only)
- **Certificate revocation** (`/ssh/revoke`): revoke certificates (admin only)
- **Portal interface**: user-friendly tab for signing SSH keys
- **Admin interface**: certificate management and revocation
- **Configurable principals**: derived from session attributes

## Requirements

- LemonLDAP::NG >= 2.23.0
- SSH CA key configured in LLNG keys store
- `ssh-keygen` available on the system

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

In the Manager under **General Parameters** > **Plugins** > **SSH CA**.

## See Also

- [SSH CA documentation](https://lemonldap-ng.org/documentation/latest/sshca)
