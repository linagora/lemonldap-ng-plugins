# SMTP/IMAP autodiscover website

Outlook and Thunderbird can use IMAP/SMTP autoconfiguration. This requires to
setup a website named `autodiscover.mydomain.tld` and handle `/autodiscover/autodiscover.xml`
queries.

This plugin permits to do it inside LLNG. You just have to add
`autodiscover.mydomain.tld` alias inside your web-server configuration to
point to LLNG portal.

This plugin also answer `404 Not found` for some specific Outlook requests.
- `/autodiscover/autodiscover.json`
- `/EWS/*`

This is a way to explain to Outlook that our server isn't an Exchange server.

Files:
- [Lemonldap::NG::Portal::Plugins::MailAutodiscover](MailAutodiscover.pm)
