# SMTP/IMAP Autodiscover

Outlook and Thunderbird can use IMAP/SMTP autoconfiguration. This requires to
setup a website named `autodiscover.mydomain.tld` and handle `/autodiscover/autodiscover.xml`
queries.

This plugin permits to do it inside LLNG. You just have to add
`autodiscover.mydomain.tld` alias inside your web-server configuration to
point to LLNG portal.

This plugin also answers `404 Not found` for some specific Outlook requests:

- `/autodiscover/autodiscover.json`
- `/EWS/*`

This is a way to explain to Outlook that our server isn't an Exchange server.

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```
sudo lemonldap-ng-store install mail-autodiscover
```

Manually: copy `lib/` into your Perl `@INC` path and add `::Plugins::MailAutodiscover` to `customPlugins` in the LLNG configuration.

## Configuration

Edit `$imapServer` and `$smtpServer` variables at the top of
`Lemonldap::NG::Portal::Plugins::MailAutodiscover` to match your mail servers.

## Files

- `lib/Lemonldap/NG/Portal/Plugins/MailAutodiscover.pm` — Plugin module
- `plugin.json` — Plugin metadata
