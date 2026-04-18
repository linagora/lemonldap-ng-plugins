<p align="center">
  <a href="https://linagora.com"><img src="linagora.png" alt="LINAGORA" width="300"></a>
</p>

# [LINAGORA](https://linagora.com)'s plugins for Lemonldap::NG

[Lemonldap::NG](https://lemonldap-ng.org/) is the leader SSO in France and one of the best Open-Source SSO in the world.

[LINAGORA](https://linagora.com) is member of [Lemonldap::NG Team](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/project_members) since 2007 and actively continues to contribute.

Several of these plugins power [**Open Bastion**](https://github.com/linagora/open-bastion), an open-source SSH bastion that relies on LemonLDAP::NG for centralized authentication and authorization. In particular, the [pam-access](plugins/pam-access), [ssh-ca](plugins/ssh-ca), [oidc-device-authorization](plugins/oidc-device-authorization), and [oidc-device-organization](plugins/oidc-device-organization) plugins provide the PAM integration, SSH certificate signing, and server enrollment used by Open Bastion.

This repository contains:

- [Plugins for `lemonldap-ng-store`](#lemonldapng-plugins)
- [LTS files](#lemonldapng-long-term-support-lts)

See also the [list of specifications (RFCs, OIDC, SAML, CAS…) implemented](SPECIFICATIONS.md)
by LLNG core and by the plugins published here.

## Lemonldap::NG plugins

These plugins are packaged for [`lemonldap-ng-store`](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/3580) _(available since LLNG 2.23.0)_ and published as a [store](https://linagora.github.io/lemonldap-ng-plugins/). They are also available as [Debian packages](#installation-with-debian-packages).

### Installation with `lemonldap-ng-store` (LLNG >= 2.23.0)

```bash
# Register this store
sudo lemonldap-ng-store add-store https://linagora.github.io/lemonldap-ng-plugins/

# List available plugins
lemonldap-ng-store list

# Install a plugin
sudo lemonldap-ng-store install <plugin-name> --activate
```

### Quick try with Docker

While waiting for the LLNG 2.23.0 release, you can try the plugins out of the box
with the [`yadd/lemonldap-ng-*`](https://github.com/guimard/llng-docker) Docker images
(tags `>= 2.22` or `latest`). The [base image](https://github.com/guimard/llng-docker/blob/master/base/Dockerfile)
installs `linagora-lemonldap-ng-store` and pre-registers this store, so
`lemonldap-ng-store install <plugin>` works immediately inside the container.

```bash
docker run --rm -it -p 80:80 yadd/lemonldap-ng-full:latest
# then, inside the container:
lemonldap-ng-store list
lemonldap-ng-store install oidc-par --activate
```

Available images include `lemonldap-ng-full`, `lemonldap-ng-portal`,
`lemonldap-ng-manager`, etc. (see the
[docker-compose examples](https://github.com/guimard/llng-docker#docker-compose-examples)).

### Manual installation

See doc of wanted plugin.

### Installation with Debian packages

All plugins are also available as Debian packages. A [Debian repository](https://linagora.github.io/lemonldap-ng-plugins/debian) is published alongside the store.

```bash
# Import the GPG key
curl -fsSL https://linagora.github.io/lemonldap-ng-plugins/store-key.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/linagora-llng-plugins.gpg

# Add the repository
echo "deb [signed-by=/usr/share/keyrings/linagora-llng-plugins.gpg] https://linagora.github.io/lemonldap-ng-plugins/debian stable main" \
  | sudo tee /etc/apt/sources.list.d/linagora-llng-plugins.list

# Install plugins
sudo apt update
sudo apt install linagora-lemonldap-ng-plugin-json-file
```

The Manager rebuild is triggered only once via dpkg triggers, even when installing multiple plugins simultaneously.

> **LLNG < 2.24.0:** the `linagora-lemonldap-ng-store` package is available in this repository and provides `lemonldap-ng-store` for older LemonLDAP::NG versions. It is pulled automatically when needed.

> **LLNG < 2.23.0:** if you use plugins with manager-overrides, install the `linagora-llng-build-manager-files` package to get `llng-build-manager-files` with `--plugins-dir` support:
>
> ```bash
> sudo apt install linagora-llng-build-manager-files
> ```

### Available plugins

| Plugin                                                       | Description                                                | Status |
| ------------------------------------------------------------ | ---------------------------------------------------------- | ------ |
| [matrix-token-exchange](plugins/matrix)                      | Matrix federation token exchange for OIDC relying parties  | stable |
| [reports](plugins/reports)                                   | Session and browser usage reports (CSV)                    | stable |
| [mail-autodiscover](plugins/mail-autodiscover)               | SMTP/IMAP autodiscover for Outlook and Thunderbird         | stable |
| [json-file](plugins/json-file)                               | JSON file-based Auth/UserDB backend for dev/test           | stable |
| [pam-access](plugins/pam-access)                             | PAM access token generation and authorization for SSH/sudo | beta   |
| [ssh-ca](plugins/ssh-ca)                                     | SSH Certificate Authority                                  | beta   |
| [twake](plugins/twake)                                       | Twake well-known endpoint and applicative accounts         | beta   |
| [fixed-logout-redirection](plugins/fixed-logout-redirection) | Force redirect to a fixed URL after logout                 | beta   |
| [external-menu](plugins/external-menu)                       | Redirect authenticated users to an external menu URL       | beta   |

#### OIDC extensions

| Plugin                                                         | Description                                               | Status |
| -------------------------------------------------------------- | --------------------------------------------------------- | ------ |
| [pacc](plugins/pacc)                                           | PACC — Provider Automatic Configuration for Clients       | beta   |
| [oidc-jarm](plugins/oidc-jarm)                                 | JARM — JWT Secured Authorization Response Mode (RFC 9207) | beta   |
| [oidc-par](plugins/oidc-par)                                   | Pushed Authorization Requests (RFC 9126)                  | beta   |
| [oidc-ciba](plugins/oidc-ciba)                                 | Client-Initiated Backchannel Authentication (CIBA)        | beta   |
| [oidc-device-authorization](plugins/oidc-device-authorization) | Device Authorization Grant (RFC 8628)                     | beta   |
| [oidc-device-organization](plugins/oidc-device-organization)   | Organization Device Ownership for Device Auth             | beta   |
| [oidc-scope-applications](plugins/oidc-scope-applications)     | Portal application menu in OIDC userinfo                  | beta   |
| [oidc-federation](plugins/oidc-federation)                     | OpenID Connect Federation (server side)                   | beta   |
| [oidc-global-scopes](plugins/oidc-global-scopes)               | Global OIDC scopes and claim mapping for all RPs          | beta   |

### Companion Debian packages

Extra Debian-only packages published in the same APT repository, for use
outside the `lemonldap-ng-store` workflow:

| Package                          | Description                                                                                                                                                                                                 |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `linagora-llng-crowdsec-filters` | [CrowdSec-compatible HTTP filters](crowdsec-filters) for `crowdsecFilters` — scanners, admin probes, CVE exploit signatures. Installs to `/var/lib/lemonldap-ng/crowdsec-filters/`. Requires LLNG ≥ 2.23.0. |

## Lemonldap::NG Long Term Support by LINAGORA (LTS)

Here are the Lemonldap::NG "LTS" versions:

| Version | Community LTS | [Debian](https://www.debian.org) LTS[^1] | Limit[^2] |
| ------- | ------------- | ---------------------------------------- | --------- |
| 2.0.11  | ❌[^3]        | ✅                                       | 2026      |
| 2.16.x  | ✅            | ✅                                       | 2028      |
| 2.21.x  | ✅            | ✅                                       | 2030      |

- [LTS community files](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/releases) for 2.16.x and 2.21.x
- [LINAGORA files for 2.0.11](./v2.0.11)

## License and copyright

Copyright: 2024-2026 [LINAGORA](https://linagora.com)

Following [Lemonldap::NG](https://lemonldap-ng.org/) License, all files here
are released under **GPL-2+ license**, unless specified:

> These files are free softwares; you can redistribute it and/or modify
> it under the terms of the GNU General Public License as published by
> the Free Software Foundation; either [version 2](./LICENSE), or (at your option)
> any later version.
>
> This program is distributed in the hope that it will be useful,
> but WITHOUT ANY WARRANTY; without even the implied warranty of
> MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
> GNU General Public License for more details.
>
> You should have received a [copy of the GNU General Public License](./LICENSE)
> along with this program. If not, see http://www.gnu.org/licenses/.

[^1]: [Official Debian repository](https://tracker.debian.org/pkg/lemonldap-ng)

[^2]: Possible extension via [LINAGORA's OSSA](https://linagora.com/ossa)

[^3]: Supported here
