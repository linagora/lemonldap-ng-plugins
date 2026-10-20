# Mongolian language (mn)

Adds the Mongolian language (Монгол) to the LemonLDAP::NG portal.

This plugin ships no Perl code: it installs a new language next to the core
ones, not an override of an existing file.

| File                              | Installed as                                   |
| --------------------------------- | ---------------------------------------------- |
| `portal-static/languages/mn.json` | `<portal static dir>/languages/mn.json`        |
| `portal-static/common/mn.png`     | `<portal static dir>/common/mn.png` (the flag) |

The portal static dir is `/usr/share/lemonldap-ng/portal/htdocs/static` on
Debian.

## Installation

With `lemonldap-ng-store`:

```bash
sudo lemonldap-ng-store install lang-mn
```

With the Debian repository:

```bash
sudo apt install linagora-lemonldap-ng-plugin-lang-mn
```

Manually: copy the content of `portal-static/` into the portal static
directory.

## Configuration

The language list of the portal is set in `lemonldap-ng.ini`. Add `mn` to the
`languages` parameter of the `[portal]` section, then reload the portal:

```ini
[portal]
languages = en, fr, mn
```

The flag then appears in the language choice of the portal, and browsers
sending `Accept-Language: mn` get the portal in Mongolian.

## Limitations

- Only the portal interface is translated. Mails sent by the portal (password
  reset, register, …) fall back to English, as there is no
  `templates/common/mail/mn.json`.
- The `/languages` endpoint of the REST server returns the language without a
  name: the language names come from `Lemonldap::NG::Common::Languages`,
  which does not know `mn`.
- The file covers the keys of the LLNG version it was made for: a key added
  in a later version is displayed as its raw name until this file is updated.
- Other plugins of this store only ship their own messages for some languages
  (`portal-translations/`), never `mn`: their messages are displayed as their
  raw name in Mongolian.
