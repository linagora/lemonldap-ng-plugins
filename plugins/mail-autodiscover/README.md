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

With `lemonldap-ng-store` _(LLNG >= 2.24.0)_ or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```
sudo lemonldap-ng-store install mail-autodiscover --activate
```

Manually: copy `lib/` into your Perl `@INC` path and add `::Plugins::MailAutodiscover` to `customPlugins` in the LLNG configuration.

## Configuration

Set the following custom parameters in the LLNG configuration (Manager →
_General Parameters_ → _Plugins custom parameters_, or directly in `lemonldap-ng.ini`):

| Parameter                    | Description      | Default            |
| ---------------------------- | ---------------- | ------------------ |
| `mailAutodiscoverImapServer` | IMAP server name | `imap.example.com` |
| `mailAutodiscoverSmtpServer` | SMTP server name | `smtp.example.com` |
| `mailAutodiscoverImapPort`   | IMAP port        | `993`              |
| `mailAutodiscoverSmtpPort`   | SMTP port        | `465`              |

When a parameter is not set, the corresponding default above is used.

## Files

- `lib/Lemonldap/NG/Portal/Plugins/MailAutodiscover.pm` — Plugin module
- `plugin.json` — Plugin metadata
