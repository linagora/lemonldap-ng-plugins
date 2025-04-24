# Patches for v2.0.11

* [Cumulative security patch](./cumulative-security.patch), fixes:
  - [CVE-2021-35472](https://security-tracker.debian.org/tracker/CVE-2021-35472)
  - [CVE-2021-35473](https://security-tracker.debian.org/tracker/CVE-2021-35473)
  - [Domain wild-card issue](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/2477)
  - [Trusted domain regex](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/2535)
  - [XSS on register form](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/2495)
  - [CVE-2021-40874](https://security-tracker.debian.org/tracker/CVE-2021-40874)
  - [CVE-2022-37186](https://security-tracker.debian.org/tracker/CVE-2022-37186)
  - [URL validation bypass](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/2832)
  - [CVE-2023-28862](https://security-tracker.debian.org/tracker/CVE-2023-28862)
  - [Open redirection when OIDC RP isn't configured](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/3003)
  - [Open redirection](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/2931)
  - [CVE-2023-44469](https://security-tracker.debian.org/tracker/CVE-2023-44469)
  - [CVE-2024-48933](https://security-tracker.debian.org/tracker/CVE-2024-48933)
  - [CVE-2024-52946](https://security-tracker.debian.org/tracker/CVE-2024-52946)
  - [CVE-2024-52947](https://security-tracker.debian.org/tracker/CVE-2024-52947)
  - [CVE-2025-31510](https://security-tracker.debian.org/tracker/CVE-2025-31510)
* [Corresponding Debian packages](./lemonldap-ng-2.0.11+linagora-1.deb.tar.gz)[^1]


[^1]: you can use [official Debian packages](https://packages.debian.org/search?keywords=lemonldap&searchon=names&suite=bullseye&section=main)
but they need some Debian additional dependencies. [These packages](./lemonldap-ng-2.0.11+linagora-1.deb.tar.gz)
reproduce the community build with security patches.
