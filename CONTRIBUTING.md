# Contributing

Thanks for helping improve the LemonLDAP::NG plugins collection! This
file explains how to set up a local testing environment for a plugin —
both by hand and via the MCP server shipped with this repo.

Every plugin is a standalone Perl bundle that ships its own `lib/`,
`t/`, templates and assets. Running its test suite requires grafting
those files into a live LemonLDAP::NG checkout so that `prove` can see
them alongside the core modules.

## One-time setup

Install the Node.js tooling once (the MCP server + the standalone CLI
share the same core and both need this):

```sh
cd mcp
npm install
```

Node.js **18 or later** is required. No system-wide install is
performed — everything lives under `mcp/node_modules/` (git-ignored).

The first run of any test command will:

1. Shallow-clone LemonLDAP::NG into `.llng-test/lemonldap-ng/`
   (git-ignored). Override with the `LLNG_REPO_URL` env var if you need
   a fork or a specific mirror.
2. Run `make common` inside that checkout (needed because the `Common`
   component uses autosplit modules that live under `blib/lib/`).

After that, every subsequent prepare reuses the same clone, so only the
symlinks change between runs.

## Testing without AI — CLI

The CLI `mcp/cli.js` wraps the exact same operations the MCP server
exposes. Call it directly from anywhere in the repo:

```sh
./mcp/cli.js list                      # list plugins available under plugins/
./mcp/cli.js test  ssh-ca              # prepare + prove in one go
./mcp/cli.js prepare ssh-ca            # just graft the plugin into LLNG
./mcp/cli.js execute ssh-ca            # just run prove (prepare must have happened)
./mcp/cli.js execute ssh-ca -- t/01-SSHCA-mycerts.t   # run one specific .t
./mcp/cli.js clean ssh-ca              # remove that plugin's symlinks + un-merge translations
./mcp/cli.js clean                     # clean every plugin (keeps the LLNG clone)
./mcp/cli.js clean-all                 # nuke .llng-test/ entirely
```

Prepare / test options:

| Flag           | Meaning                                                                                                                                                              |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--ref <tag>`  | Clone LLNG at a specific git ref (tag or branch). If the ref can't be reached, falls back to the default branch. Changing ref between runs wipes the previous clone. |
| `--skip-make`  | Skip `make common` on repeat runs                                                                                                                                    |
| `--no-deps`    | Don't auto-resolve `plugin.json:depends`                                                                                                                             |
| `--with a,b,c` | Also link extra plugins (lib + assets only; their tests are not linked)                                                                                              |
| `--quiet`      | Non-verbose `prove`                                                                                                                                                  |

If you prefer a shorter name, `npm install` also registers the CLI as
`llng-plugins-test` — symlink it or add `mcp/node_modules/.bin` to
your `PATH`.

### What it does, step by step

Running `test ssh-ca` is equivalent to doing this by hand:

```sh
# 1. Clone LLNG (shallow) — only the first time
git clone --depth 1 https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng.git \
         .llng-test/lemonldap-ng
cd .llng-test/lemonldap-ng

# 2. Build the Common blib tree
make common

# 3. Symlink plugin sources into the LLNG tree
ln -s $PWD/../../plugins/ssh-ca/lib/Lemonldap/NG/Portal/Plugins/SSHCA.pm \
      lemonldap-ng-portal/lib/Lemonldap/NG/Portal/Plugins/SSHCA.pm
# ... same for every .pm, .tpl, .js, .t

# 4. Merge the plugin's language keys into the portal's en.json / fr.json
#    (additive — core keys are never overwritten)

# 5. Run prove in the correct component dir
cd lemonldap-ng-portal
prove -v -I. \
      -I../lemonldap-ng-common/blib/lib \
      -I../lemonldap-ng-handler/lib \
      -I../lemonldap-ng-manager/lib \
      -I../lemonldap-ng-portal/lib \
      t/01-SSHCA-mycerts.t t/02-SSHCA-admin.t
```

The CLI just automates all of this and tracks the merged translation
keys in `.llng-test/state/<plugin>/translations.json` so that `clean`
can un-merge them without losing LLNG's core strings.

## Testing with AI — MCP server

The repo ships a `.mcp.json` at its root. If you run an MCP-aware
client (Claude Code, Cursor, …) from this directory, it auto-discovers
the `llng-plugins` server and exposes six tools: `list-plugins`,
`prepare-test`, `execute-test`, `clean-test`, `clean-all`, `test`.

From there you just ask:

> test the ssh-ca plugin

and the agent runs `prepare-test` + `execute-test`, inspects any
failures, and can iterate.

Don't forget the one-time `cd mcp && npm install` — without it the
MCP server cannot start.

### Picking between the two

| You're…                                             | Use                                         |
| --------------------------------------------------- | ------------------------------------------- |
| writing code in your editor, running tests yourself | the CLI (`./mcp/cli.js …`)                  |
| asking an AI agent to fix / extend a plugin         | the MCP server                              |
| writing a CI pipeline                               | the CLI (exit codes propagate from `prove`) |

Both talk to the same `lib.js`, so results are identical.

## Plugin layout

The tooling understands the following plugin directory structure:

```
plugins/<your-plugin>/
├── plugin.json           # metadata (name, version, depends, …)
├── lib/
│   └── Lemonldap/NG/
│       ├── Common/...     -> linked into lemonldap-ng-common/blib/lib/
│       ├── Portal/...     -> linked into lemonldap-ng-portal/lib/
│       ├── Handler/...    -> linked into lemonldap-ng-handler/lib/
│       └── Manager/...    -> linked into lemonldap-ng-manager/lib/
├── t/                    # .t files + optional subdirs like t/lib/
├── portal-templates/      # *.tpl, typically under bootstrap/
├── portal-static/         # JS/CSS under common/...
├── manager-static/        # optional, if you extend the manager UI
├── portal-translations/   # {en,fr,…}.json — additive merge into static/languages/
├── manager-overrides/     # not linked by the test tooling
└── README.md
```

The "primary" component for running tests is chosen by scanning the
plugin's `.pm` files (priority: `Portal > Handler > Manager > Common`).
Tests are linked into, and `prove` runs from, that component's
directory.

## Dependencies between plugins

If your plugin needs another plugin at runtime, list it in
`plugin.json`:

```json
{
  "name": "oidc-device-organization",
  "depends": ["oidc-device-authorization"],
  …
}
```

Both CLI and MCP walk this transitively: the dependency is grafted
before the primary plugin. Only the primary's `t/` is linked —
dependencies contribute runtime code, not test suites.

Use `--with foo,bar` (CLI) or `with: ["foo", "bar"]` (MCP) to add
plugins that aren't formally declared as dependencies.

## Cleaning up

Cleaning is safe and idempotent:

- `clean <plugin>` — only removes that plugin's symlinks and un-merges
  its translation keys. Other plugins and the LLNG clone are kept.
- `clean` — every plugin, clone kept.
- `clean-all` — deletes `.llng-test/` entirely. Next run re-clones.

Both the clone and any state files live under `.llng-test/`, which is
in `.gitignore` — nothing from the test environment ever leaks into a
commit.

## Continuous integration

The GitHub Actions workflow in `.github/workflows/test.yml` runs on
top of the very same CLI. For each plugin it reads `plugin.json:llng_compat`
and builds a test matrix:

| `llng_compat`                              | Refs tested                                                                                           |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| `>=X.Y.Z` and tag `vX.Y.Z` exists          | **both** `vX.Y.Z` and the LLNG default branch (catches regressions between release and HEAD)          |
| `>=X.Y.Z` and the tag is not yet published | default branch only                                                                                   |
| `<X.Y.Z` and tag `vX.Y.Z` exists           | `vX.Y.Z` only — the default branch is **skipped** (plugin declares it doesn't support newer versions) |
| no `llng_compat`                           | default branch only                                                                                   |

Ranges (`>=A, <B`) are supported — each bound contributes its own tag
to the matrix, and a satisfied `<` still removes the default branch.

Each matrix job does the same thing a contributor does locally:

```sh
cd mcp && npm install --no-audit --no-fund
./mcp/cli.js prepare <plugin> [--ref <tag>]
# (CI installs LLNG's build deps from debian/control + plugin.build_depends)
./mcp/cli.js execute <plugin>
```

Exit code from `prove` propagates all the way up, so a failing test
fails the job.

## Environment overrides

| Variable            | Default                                                |
| ------------------- | ------------------------------------------------------ |
| `LLNG_REPO_URL`     | `https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng.git` |
| `LLNG_PLUGINS_ROOT` | the repo root (parent of `mcp/`)                       |

Set these if you need to test against a private fork or a
non-standard layout.

## Writing a new plugin

1. Create `plugins/<your-plugin>/` with the layout above.
2. Drop your Perl modules into `lib/Lemonldap/NG/<Component>/...`.
3. Put tests under `t/` — they will be linked into
   `lemonldap-ng-<primary>/t/`, so `use lib 't/lib';` and similar
   patterns work out of the box.
4. `./mcp/cli.js test <your-plugin>` and iterate.
5. `./mcp/cli.js clean-all` before committing if you want a clean
   working tree (not strictly required — `.llng-test/` is ignored).
