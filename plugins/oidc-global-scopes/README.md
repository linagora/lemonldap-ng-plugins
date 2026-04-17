# OIDC Global Scopes

Adds global OIDC scope definitions that apply to **all** relying parties,
without requiring per-RP configuration.

## Features

- **Enrich existing scopes**: add extra claims to standard scopes like
  `profile`, `email`, etc.
- **Define new scopes**: create entirely new scopes with associated claims,
  available for all RPs
- **Manager UI**: configure via the OIDC Service scopes section
- **Non-intrusive**: standard claims and per-RP `extraClaims` keep working;
  global claims are added on top

## Requirements

- LemonLDAP::NG >= 2.23.0
- OIDC issuer must be enabled

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```bash
sudo lemonldap-ng-store install oidc-global-scopes --activate
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-overrides.d/`, add
`::Plugins::OIDCGlobalScopes` to `customPlugins`, and run
`llng-build-manager-files`.

## Configuration

In the Manager, go to **OIDC Service > Scopes** and configure
**Global extra scopes** (`oidcServiceGlobalExtraScopes`):

| Key (scope)  | Value (claims)                      |
| ------------ | ----------------------------------- |
| `profile`    | `department employee_id`            |
| `corporate`  | `department manager office_location`|

Each key is a scope name (existing or new), and each value is a
space-separated list of claim names.

### Claim resolution

For each global claim, the plugin looks up the source session attribute
in this order:

1. **RP Exported Attributes** (`oidcRPMetaDataExportedVars`) — wins if
   the RP has declared the claim, so per-RP type/array overrides keep
   working.
2. **Global claim mapping** (`oidcServiceGlobalClaimMapping`) — fallback
   used when the RP hasn't declared the claim. Same syntax as
   `oidcRPMetaDataExportedVars` values: `sessionAttr` or
   `sessionAttr;type;array`.
3. **Identity** — if neither is set, the claim name itself is used as
   the session attribute (e.g. claim `department` pulls session
   attribute `department`).

Missing session values are silently skipped.

Example global mapping:

| Key (claim)       | Value (session attribute)          |
| ----------------- | ---------------------------------- |
| `department`      | `department`                       |
| `office_location` | `physicalDeliveryOfficeName`       |
| `roles`           | `groups;string;array`              |

## How it works

The plugin uses two OIDC hooks:

1. **`oidcResolveScope`**: ensures globally-defined scopes survive
   filtering when `oidcServiceAllowOnlyDeclaredScopes` is enabled
2. **`oidcGenerateUserInfoResponse`**: adds the configured claims to the
   userinfo response for each granted global scope

Claims already set by the OIDC core or per-RP configuration are not
overwritten.

## Examples

### Add department to the profile scope

```
oidcServiceGlobalExtraScopes:
  profile: department
```

When any RP requests `scope=openid profile`, the userinfo will include
the standard profile claims **plus** `department` (provided the RP has
`department` in its exported vars).

### Define a new corporate scope

```
oidcServiceGlobalExtraScopes:
  corporate: department manager office_location
```

Any RP can then request `scope=openid corporate` to receive those three
claims.
