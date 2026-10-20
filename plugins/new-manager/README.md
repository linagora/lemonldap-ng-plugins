# New manager

Backport of the new LemonLDAP::NG 3.0 manager interface (React) to
LemonLDAP::NG 2.23: configuration, sessions, notifications and second factors
explorers, plus a home page summarizing the enabled modules.

The historical interface stays the default. Each user switches with the
"New manager (beta)" tab of the historical interface, and back with the
"Back to the classic manager" link of the new one (a `llngmanagerbeta`
cookie, like in LLNG 3.0).

This plugin is obsolete with LLNG >= 3.0, which ships this interface.

## Installation

With the Debian packages: `apt install linagora-lemonldap-ng-plugin-new-manager`.

With `lemonldap-ng-store` _(LLNG >= 2.24.0)_ or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```
sudo lemonldap-ng-store install new-manager
```

Then append `newManager` to `enabledModules` in the `[manager]` section of
`lemonldap-ng.ini`, **never first** (the first module gives the default page),
and reload the manager:

```ini
[manager]
enabledModules = conf, sessions, notifications, 2ndFA, newManager
```

## How it works

- `Lemonldap::NG::Manager::NewManager` (the `newManager` module) reblesses
  the manager object into `Lemonldap::NG::Manager::NewManager::Core`, which
  backports the LLNG 3.0 interface switch: templates searched in
  `templates/new/` first, CSP allowing the MUI runtime styles, `version` in
  `psgi.js` and the home page on `/`.
- The bundles are the readable (non minified) build of the LLNG new manager,
  patched for the 2.23 APIs (2FA routes, notification body).
- The configuration metadata of the new interface (`static/nstruct.json`,
  `static/new/{attributes,definitions,tree}.json`) is shipped for the 2.23
  schema. When `linagora-llng-build-manager-files` is installed, rebuilding
  the manager regenerates it with the parameters added by the other plugins.

## Updating

Run `make new_manager` in a LemonLDAP::NG checkout, then:

```
plugins/new-manager/scripts/import <llng-checkout> [<llng-2.23-tag>]
```

## Files

- `lib/Lemonldap/NG/Manager/NewManager.pm` — manager module (`newManager`)
- `lib/Lemonldap/NG/Manager/NewManager/Core.pm` — interface switch
- `manager-static/` — bundles and configuration metadata
- `manager-templates/new/` — HTML templates of the new interface
- `manager-overrides/new-manager.json` — translations missing in 2.23
- `scripts/import` — import from a LemonLDAP::NG checkout
