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

| Parameter                    | Environment variable                | Description      | Default            |
| ---------------------------- | ----------------------------------- | ---------------- | ------------------ |
| `mailAutodiscoverImapServer` | `LLNG_MAILAUTODISCOVER_IMAP_SERVER` | IMAP server name | `imap.example.com` |
| `mailAutodiscoverSmtpServer` | `LLNG_MAILAUTODISCOVER_SMTP_SERVER` | SMTP server name | `smtp.example.com` |
| `mailAutodiscoverImapPort`   | `LLNG_MAILAUTODISCOVER_IMAP_PORT`   | IMAP port        | `993`              |
| `mailAutodiscoverSmtpPort`   | `LLNG_MAILAUTODISCOVER_SMTP_PORT`   | SMTP port        | `465`              |

Each value is resolved with the following precedence: **environment variable**
(highest priority) → LLNG custom parameter → built-in default. This makes the
plugin convenient to configure in containerized deployments (Docker, Helm).

## Files

- `lib/Lemonldap/NG/Portal/Plugins/MailAutodiscover.pm` — Plugin module
- `plugin.json` — Plugin metadata
