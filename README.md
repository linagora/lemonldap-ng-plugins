# Linagora's plugins for Lemonldap::NG

[Lemonldap::NG](https://lemonldap-ng.org/) is the leader SSO in France and one of the best Open-Source SSO in the world.

Linagora is member of [Lemonldap::NG Team](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/project_members) since 2007 and actively continue to contributes.

This repository contains:
- [Various plugins not yet included](#lemonldapng-additional-plugins):
- [LTS files](#long-term-support-lts)

## Lemonldap::NG additional plugins

  - [Lemonldap::NG::Portal::Plugins::MatrixTokenExchange](plugins/matrix): Matrix token exchanger
  - [Lemonldap::NG::Portal::Plugins::Reports](plugins/reports): various reports
  - [Lemonldap::NG::Portal::Plugins::MailAutodiscover](plugins/mail-autodiscover): handles autodiscover.mydomain.tld/autodiscover requests

## Long Term Support (LTS)

Here are the Lemonldap::NG "LTS" versions:

| Version | Community LTS | Debian LTS[^1] | Limit[^2] |
| ------- | ------------- | -------------- | --------- |
|  2.0.11 |      ❌[^3]   |       ✅       |    2026   |
|  2.16.x |      ✅       |       ✅       |    2028   |
|  2.21.x |      ✅       |       ✅       |    2030   |


- [LTS community files](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/releases) for 2.16.x and 2.21.x
- [Linagora files for 2.0.11](./v2.0.11)

## License and copyright

Following [Lemonldap::NG](https://lemonldap-ng.org/) License, all files here
are released under **GPL-2+ license[^4]**, copyright
[Linagora](https://linagora.com/), unless specified.

[^1]: [Official Debian repository](https://tracker.debian.org/pkg/lemonldap-ng)
[^2]: Possible extension via [Linagora's OSSA](https://linagora.com/ossa)
[^3]: Supported here
[^4]: Either [GNU General Pulic License version 2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html) or any later version of this license
