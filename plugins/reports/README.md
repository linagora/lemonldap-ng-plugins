# Reports

This plugins permits to get an image of what browsers/apps are connected to LLNG.
This is an instant image, no history in it.

APIs:
- **Only if sessions are stored into a PostgreSQL database**, but easy to adapt:
  - `/reports/apps`: CSV list of softwares connected using OpenID-Connect "offline\_access" _(mostly phone apps)_
  - `/reports/browsers`: CSV list of browsers connected
- **Only if user backend is LDAP and sessions are stored into a PostgreSQL database**, but easy to adapt:
  - `/reports/lastcnx`: CSV list of users with their last connexion time

Files:
- [Lemonldap::NG::Portal::Plugins::Reports](./Reports.pm)
