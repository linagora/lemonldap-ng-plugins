# Linagora's plugins for Lemonldap::NG

[Lemonldap::NG](https://lemonldap-ng.org/) is the leader SSO in France and one of the best Open-Source SSO in the world.

Linagora is member of [Lemonldap::NG Team](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/project_members) since 2007 and actively continue to contributes.

This repository contains:
- [Various plugins not yet included](#lemonldapng-additional-plugins):
- [LTS files](#lemonldapng-long-term-support-lts)

## Lemonldap::NG additional plugins

  - [Lemonldap::NG::Portal::Plugins::MatrixTokenExchange](plugins/matrix): Matrix token exchanger
  - [Lemonldap::NG::Portal::Plugins::Reports](plugins/reports): various reports
  - [Lemonldap::NG::Portal::Plugins::MailAutodiscover](plugins/mail-autodiscover): handles `https://autodiscover.mydomain.tld/autodiscover/*` requests

## Lemonldap::NG Long Term Support (LTS)

Here are the Lemonldap::NG "LTS" versions:

| Version | Community LTS | [Debian](https://www.debian.org) LTS[^1] | Limit[^2] |
| ------- | ------------- | ---------------------------------------- | --------- |
|  2.0.11 |      ❌[^3]   |                    ✅                    |    2026   |
|  2.16.x |      ✅       |                    ✅                    |    2028   |
|  2.21.x |      ✅       |                    ✅                    |    2030   |


- [LTS community files](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/releases) for 2.16.x and 2.21.x
- [Linagora files for 2.0.11](./v2.0.11)

## License and copyright

Copyright: 2025 [Linagora](https://linagora.com)

Following [Lemonldap::NG](https://lemonldap-ng.org/) License, all files here
are released under **GPL-2+ license**, unless specified:

> These files are free softwares; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either [version 2](./LICENSE), or (at your option)
any later version.
>
> This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
>
> You should have received a [copy of the GNU General Public License](./LICENSE)
along with this program.  If not, see http://www.gnu.org/licenses/.

[^1]: [Official Debian repository](https://tracker.debian.org/pkg/lemonldap-ng)
[^2]: Possible extension via [Linagora's OSSA](https://linagora.com/ossa)
[^3]: Supported here
