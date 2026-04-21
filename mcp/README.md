# LemonLDAP::NG plugins — local-test MCP server

A small [MCP](https://modelcontextprotocol.io/) server that automates the
plumbing needed to run a plugin's Perl test suite against a real
LemonLDAP::NG checkout.

It takes care of:

1. **Cloning** LemonLDAP::NG into a hidden, git-ignored directory
   (`.llng-test/lemonldap-ng/`) on first use (`git clone --depth 1`).
2. **Building** the `lemonldap-ng-common/blib/lib` tree with `make common`
   (needed because `Common` ships autosplit modules).
3. **Symlinking** the plugin's `lib/` files into the correct LLNG component
   (Portal / Handler / Manager / Common), its `t/` files into that
   component's `t/` directory, its `portal-templates/`, `portal-static/`
   and `manager-static/` into the matching site trees.
4. **Merging** `portal-translations/{en,fr,…}.json` into
   `lemonldap-ng-portal/site/htdocs/static/languages/` additively
   (never overwrites a core key; un-merge is tracked per plugin).
5. **Resolving dependencies**: plugins declared in the primary plugin's
   `plugin.json:depends` are linked transitively (lib + assets only —
   their tests are not auto-linked).
6. **Running** `prove` with the canonical `-I` flag set.
7. **Cleaning up** symlinks + un-merging translation keys — optionally
   the whole clone.

## Install

```sh
cd mcp
npm install
```

Node.js 18+ is required. This install is mandatory both for the MCP
server and for the standalone CLI (`cli.js`): they share the same
dependencies (`@modelcontextprotocol/sdk`).

## Two entry points

- `server.js` — stdio MCP server (consumed by Claude Code, Cursor, …).
- `cli.js` — standalone CLI for humans and CI. Same operations, no AI
  required. Run `./mcp/cli.js --help` or see CONTRIBUTING.md for the
  full usage.

## Register with Claude Code

The repo ships a `.mcp.json` at its root, so running Claude Code from
this folder picks up the server automatically. For a global
registration, add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "llng-plugins": {
      "command": "node",
      "args": ["/absolute/path/to/lemonldap-ng-plugins/mcp/server.js"]
    }
  }
}
```

## Tools

| Tool           | What it does                                                                                                                                                                                                                                                                                                                    |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `list-plugins` | Lists every directory under `plugins/`.                                                                                                                                                                                                                                                                                         |
| `prepare-test` | Clones LLNG if absent, runs `make common`, symlinks lib + t + assets + merges translations. Follows `depends` transitively unless `noDeps:true`. Params: `plugin` (required), `with` (extra plugins), `noDeps`, `skipMake`, `ref` (git tag/branch; falls back to default branch if unreachable, wipes the clone on ref change). |
| `execute-test` | Runs `prove` in the primary plugin's LLNG component dir. Params: `plugin` (required), `tests` (optional array), `verbose`.                                                                                                                                                                                                      |
| `clean-test`   | Removes the plugin's symlinks + un-merges its translation keys. Params: `plugin` or `plugins` to scope; omit both to clean every plugin. The LLNG clone is kept.                                                                                                                                                                |
| `clean-all`    | `clean-test` **and** wipes `.llng-test/` entirely. Use to start fresh.                                                                                                                                                                                                                                                          |
| `test`         | Convenience: `prepare-test` then `execute-test`. Cleanup is not performed automatically.                                                                                                                                                                                                                                        |

### Plugin → LLNG layout

| Plugin dir                     | LLNG destination                                                                                                                     |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| `lib/Lemonldap/NG/Common/...`  | `lemonldap-ng-common/blib/lib/Lemonldap/NG/Common/...`                                                                               |
| `lib/Lemonldap/NG/Portal/...`  | `lemonldap-ng-portal/lib/Lemonldap/NG/Portal/...`                                                                                    |
| `lib/Lemonldap/NG/Handler/...` | `lemonldap-ng-handler/lib/Lemonldap/NG/Handler/...`                                                                                  |
| `lib/Lemonldap/NG/Manager/...` | `lemonldap-ng-manager/lib/Lemonldap/NG/Manager/...`                                                                                  |
| `t/`                           | `lemonldap-ng-<primary>/t/` (including sub-trees like `t/lib/`)                                                                      |
| `portal-templates/`            | `lemonldap-ng-portal/site/templates/`                                                                                                |
| `portal-static/`               | `lemonldap-ng-portal/site/htdocs/static/`                                                                                            |
| `manager-static/`              | `lemonldap-ng-manager/site/htdocs/static/`                                                                                           |
| `portal-translations/*.json`   | **merged** into `.../static/languages/*.json` (added keys are tracked in `.llng-test/state/<plugin>/translations.json` for un-merge) |

A plugin's primary component is picked by scanning its `.pm` files,
with priority `Portal > Handler > Manager > Common`. That component's
directory is where the plugin's tests are linked and where `prove`
runs.

### The `prove` command

`execute-test` invokes:

```
prove -v -I. \
      -I../lemonldap-ng-common/blib/lib \
      -I../lemonldap-ng-handler/lib \
      -I../lemonldap-ng-manager/lib \
      -I../lemonldap-ng-portal/lib \
      t/...
```

from inside the primary plugin's component directory (usually
`.llng-test/lemonldap-ng/lemonldap-ng-portal/`).

### Multi-plugin linking

Example: `oidc-device-organization` declares
`"depends": ["oidc-device-authorization"]` in its `plugin.json`.
Running `prepare-test { plugin: "oidc-device-organization" }` links
both plugins in order (dep first, primary last). Use
`with: ["other-plugin"]` to add further plugins or
`noDeps: true` to skip auto-resolution.

Only the **primary** plugin's `t/` is linked. Dependencies contribute
runtime code (lib + templates + translations), not test suites.

## Environment overrides

| Variable            | Default                                                |
| ------------------- | ------------------------------------------------------ |
| `LLNG_REPO_URL`     | `https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng.git` |
| `LLNG_PLUGINS_ROOT` | Parent directory of `mcp/` (this repo's root)          |

## Typical workflow

```text
list-plugins                          -> pick, say, "ssh-ca"
test   { "plugin": "ssh-ca" }         -> one-shot: prepare + prove
clean-test { "plugin": "ssh-ca" }     -> remove ssh-ca symlinks + un-merge translations
# ...iterate on another plugin without re-cloning
clean-all                             -> full reset (drops the clone too)
```
