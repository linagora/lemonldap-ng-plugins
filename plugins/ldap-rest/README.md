# ldap-rest — password change and registration through ldap-rest

[ldap-rest](https://github.com/linagora/ldap-rest) is a lightweight directory
manager exposing an LDAP directory through a REST API, with consistency
plugins, hooks and its own authorization layer.

This plugin lets LemonLDAP::NG **write** into the directory through ldap-rest
instead of writing into LDAP directly. It provides two backends:

| Module                                    | Role         | Manager entry        |
| ----------------------------------------- | ------------ | -------------------- |
| `Lemonldap::NG::Portal::Password::LdapRest` | `passwordDB` | `LDAP (ldap-rest)`   |
| `Lemonldap::NG::Portal::Register::LdapRest` | `registerDB` | `LDAP (ldap-rest)`   |

Both share the same `ldapRest*` configuration and can be used independently.

This is useful when:

- the portal is not allowed to write into the directory itself,
- ldap-rest hooks must be triggered on password change or account creation
  (audit, propagation to other systems, …),
- directory writes must be centralized and logged in one place.

## Installation

### Via the LLNG store

```bash
sudo lemonldap-ng-store install ldap-rest
```

### Manual installation

```bash
cp -r lib/Lemonldap/NG/Portal/* /usr/share/perl5/Lemonldap/NG/Portal/
cp manager-overrides/ldap-rest.json /etc/lemonldap-ng/manager-overrides.d/
llng-build-manager-files --plugins-dir=/etc/lemonldap-ng/manager-overrides.d
```

No `customPlugins` entry and no autoload rule are needed: both modules are
loaded by the core, from the `passwordDB` and `registerDB` configuration keys.

## Configuration

In the Manager, go to `General Parameters` > `Plugins` > `ldap-rest
parameters`:

| Parameter                 | Description                                                                                             |
| ------------------------- | ------------------------------------------------------------------------------------------------------- |
| ldap-rest base URL        | Base URL of the ldap-rest service, e.g. `https://ldap-rest.example.com`. **Required.**                    |
| Resource name             | Plural name of the ldap-rest flat resource handling users. Default: `users`.                              |
| Resource main attribute   | ldap-rest `mainAttribute` of that resource, used to build the DN on creation. Default: `uid`.              |
| Entry id session key      | Session key holding the identifier to use in the ldap-rest URL on password change. Empty (default) = DN.  |
| Password attribute        | LDAP attribute to write. Default: `userPassword`.                                                         |
| Password hash scheme      | Optional client side hashing (see below).                                                                 |
| ldap-rest authentication  | `none`, `token` or `hmac`.                                                                                |
| Bearer token              | Token, when `token` is selected.                                                                          |
| HMAC service id           | Service identifier, when `hmac` is selected.                                                              |
| HMAC shared secret        | Shared secret, when `hmac` is selected.                                                                   |

Then, in `General Parameters` > `Authentication modules`, select
`LDAP (ldap-rest)` as **Password module** and/or as **Register module**.

## Password backend

Select `LDAP (ldap-rest)` as **password module**.

Reads still use the LDAP connection: ldap-rest exposes no "verify this
password" endpoint, and a simple bind is the canonical way to check the old
password. Only the write is delegated:

```text
PUT <base URL>/api/v1/ldap/<resource>/<id>
Content-Type: application/json

{"replace":{"userPassword":"<value>"}}
```

> **The LDAP connection is still required.** `General Parameters` >
> `Authentication modules` > `LDAP parameters` > `Connection` must be filled,
> and the account used to bind must be able to search the directory. It does
> **not** need write access.

`<id>` is the user DN by default. ldap-rest accepts a DN only if it is a
direct child of its configured base and if it starts with its
`mainAttribute`. If your DNs do not match (for instance `cn=…` while
ldap-rest uses `uid`), set *Entry id session key* to `uid`.

The other LDAP password options are still honored:

- `Password policy control`, `Reset attribute` and `Reset value`: the reset
  flag is written through ldap-rest as well,
- `Get user before password change`,
- `Require old password` (`Portal` > `Advanced parameters`): the old password
  is checked with an LDAP bind before calling ldap-rest.

## Register backend

Select `LDAP (ldap-rest)` as **register module**.

Unlike the password backend, this one needs **no LDAP connection at all**:
ldap-rest answers both the uniqueness check and the creation.

```text
GET  <base URL>/api/v1/ldap/<resource>/<login>   -> 404 means the login is free
POST <base URL>/api/v1/ldap/<resource>
Content-Type: application/json

{"uid":"jdoe","cn":"John DOE","sn":"DOE","givenName":"John",
 "userPassword":"…","mail":"john.doe@example.com"}
```

The login is derived by the core `Register::Base` rule (first letter of the
first name + last name, accents stripped); a counter is appended until a free
one is found. If ldap-rest cannot be questioned, registration is refused
rather than risking a duplicate account.

`objectClass` and any default attribute are **not** sent: they come from the
`entity` section of the ldap-rest schema of the flat resource. Make sure that
schema declares an object class accepting `cn`, `sn`, `givenName`, `mail` and
the configured password attribute — typically `inetOrgPerson`.

## Authentication against ldap-rest

### None

No `Authorization` header is sent. Only usable when ldap-rest is protected by
other means (network, mTLS, trusted proxy).

### Token

Uses the ldap-rest `core/auth/token` plugin:

```shell
npx ldap-rest … --plugin core/auth/token \
    --auth-token "<token>:lemonldap-ng"
```

The portal sends `Authorization: Bearer <token>`.

### HMAC

Uses the ldap-rest `core/auth/hmac` plugin:

```shell
npx ldap-rest … --plugin core/auth/hmac \
    --auth-hmac "<service-id>:<secret>:LemonLDAP::NG portal"
```

The portal sends:

```text
Authorization: HMAC-SHA256 <service-id>:<timestamp>:<signature>
```

with `signature = HMAC-SHA256(secret, "<METHOD>|<path>|<timestamp>|<sha256(body)>")`.
The body hash is empty for `GET`, `DELETE` and `HEAD`.

> The signed path is the path of the URL built from *ldap-rest base URL*. If
> ldap-rest is published behind a reverse proxy, that proxy must keep the path
> unchanged, otherwise signatures will not match.
>
> The secret should be at least 32 characters long, and the clocks of the
> portal and of the ldap-rest server must be in sync (default tolerance:
> 2 minutes).

## Password hashing

By default the password is sent in clear text to ldap-rest, which forwards it
to the directory. This is the right choice when the directory hashes it itself
(OpenLDAP with `ppolicy_hash_cleartext`, or a `pw-*` overlay).

If your directory stores what it receives, select a hash scheme (`SSHA`,
`SSHA256`, `SSHA512`, `SHA`, `SHA256`, `SHA512`): the portal then sends an
RFC 3112 value such as `{SSHA512}Base64(digest+salt)`. Salted schemes need
`Crypt::URandom`.

> Client side hashing prevents the directory from applying its own password
> quality checks (`pwdCheckQuality`, password history). Prefer server side
> hashing when possible.

The scheme applies to both backends: a password set at registration is hashed
the same way as a password changed later.

## Tests

```bash
node mcp/cli.js test ldap-rest
```

## License

GPL-2.0
