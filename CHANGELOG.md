# Changelog

## v0.1.1 — 2026-03-26

### New plugin

- **json-file**: JSON file-based Auth/UserDB backend for development and
  testing (#2). Inherits from Demo, loads users, passwords and groups from
  a JSON file configured via Manager (`jsonFileUserPath`) or
  `LLNG_JSONUSERS` environment variable. Includes manager-overrides to
  add JsonFile to the authentication and userDB select dropdowns.

## v0.1.0 - 2026-03-24

Initial store release
