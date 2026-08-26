# Custom functions

Extra functions for LemonLDAP::NG [rules, macros and
headers](https://lemonldap-ng.org/documentation/latest/customfunctions.html),
declared through the `customFunctions` configuration parameter:

| Function                      | Description                                                                      |
| ----------------------------- | -------------------------------------------------------------------------------- |
| `uuid($value, $namespace)`    | Stable name-based UUID version 5 (SHA-1, RFC 9562) of `$value`                   |
| `isPrivateIp($ip, @networks)` | True if `$ip` is in the RFC 1918 private space (or in one of the extra networks) |

Both are pure functions, compatible with the
[Safe jail](https://lemonldap-ng.org/documentation/latest/safejail.html):
there is **no** need to set `useSafeJail = 0`.

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.24.0)_ or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```bash
sudo lemonldap-ng-store install custom-functions
```

This plugin is a pure function library: it has no portal module, nothing to
add to `customPlugins` and no autoload rule.

## Configuration

Both steps are needed, on **every server** evaluating the rules, macros or
headers that use the functions (portals _and_ handlers).

### 1. Load the library

Custom functions are plain Perl code: LLNG only builds a wrapper calling
them, the module itself has to be loaded in the process. The standard way
is the `require` parameter of `lemonldap-ng.ini`:

```ini
[all]
require = /usr/share/perl5/Lemonldap/NG/Common/CustomFunctions.pm
; Prevent the portal/handler from crashing if the file is not found
;requireDontDie = 1
```

Several libraries can be listed, separated by commas.

Give a **file path**, not a module name: the ini loader
(`Lemonldap::NG::Common::Conf`) resolves that value with `require $var`,
i.e. as a file name. `require = Lemonldap::NG::Common::CustomFunctions`
does work — the Safe jail builder loads module names properly — but the ini
loader logs a spurious `Can't locate … in @INC` error at every
configuration load.

Find the installed path with:

```bash
perl -MLemonldap::NG::Common::CustomFunctions \
     -e 'print $INC{"Lemonldap/NG/Common/CustomFunctions.pm"}, "\n"'
```

Anything else loading the module works as well (a `PerlModule` directive
under `mod_perl`, `PERL5OPT=-MLemonldap::NG::Common::CustomFunctions` in the
service environment, a custom plugin `use`-ing it, …), but `require` is the
only portable way that covers portals _and_ handlers.

### 2. Declare the functions

In the Manager, under **General Parameters** » **Advanced Parameters** »
**Custom functions**, declare the functions you want to use, separated by
spaces:

```
Lemonldap::NG::Common::CustomFunctions::uuid Lemonldap::NG::Common::CustomFunctions::isPrivateIp
```

Only the last part of each name is exposed to rules and macros, so they are
called as `uuid(...)` and `isPrivateIp(...)`.

## `uuid($value, $namespace)`

Returns the [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562) (ex RFC 4122)
name-based UUID **version 5** of `$value`, in canonical lowercase form. The
same pair `(value, namespace)` always produces the same UUID, on every
server and across restarts — which makes it a good stable identifier for an
application that requires a UUID-shaped user ID.

`$namespace` is optional. It accepts:

| Value                                   | Meaning                                 |
| --------------------------------------- | --------------------------------------- |
| _(omitted)_                             | URL namespace (default)                 |
| `dns`, `url`, `oid`, `x500`             | the four predefined RFC 9562 namespaces |
| `6ba7b810-9dad-11d1-80b4-00c04fd430c8`  | any namespace UUID                      |
| `{...}`, `urn:uuid:...`, without dashes | same, alternative syntaxes              |

Use your own namespace UUID (generate one with `uuidgen`) when you want the
identifiers to be unguessable from the user name alone, or different for
each application:

```perl
# Macro: a UUID identifying the user for application A
uuid($uid, '2f4b1a10-1a2b-4c3d-8e5f-6a7b8c9d0e1f')

# Macro: a UUID computed from the mail address, DNS namespace
uuid($mail, 'dns')
```

Notes:

- the value is hashed in its UTF-8 encoded form, so results match other
  UUIDv5 implementations (`uuidgen --sha1`, Python `uuid.uuid5`, …);
- an invalid namespace raises an exception (visible in the portal logs)
  instead of silently returning a UUID that would be the same for every
  user;
- a UUIDv5 is a _hash_, not a secret: anybody who knows the namespace can
  recompute it from the value. If you need an opaque identifier that cannot
  be reversed, use LLNG's built-in `subjectid()` with a salt instead.

## `isPrivateIp($ip, @networks)`

Returns 1 if `$ip` belongs to the [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918)
private IPv4 address space:

```
10.0.0.0/8   172.16.0.0/12   192.168.0.0/16
```

Any extra argument is an additional network in CIDR notation (IPv4 or
IPv6), which lets you extend that definition to your own idea of "internal":

```perl
# Rule: internal users only
isPrivateIp($ENV{REMOTE_ADDR})

# Macro: loopback, IPv6 unique local addresses and an internal public range
# are considered private too
isPrivateIp($ipAddr, '127.0.0.0/8', '::1/128', 'fc00::/7', '203.0.113.0/24')

# Rule: skip second factor when the user comes from the LAN
isPrivateIp($ipAddr) ? 0 : 1
```

An address — or a network — that cannot be parsed yields 0, so a bad value
never breaks the evaluation of a rule.

> **Note** — behind a reverse proxy, `$ipAddr` (portal) and
> `$ENV{REMOTE_ADDR}` (handler) hold the address LLNG resolved, honouring
> `X-Forwarded-For` when `trustedProxies` is configured. Make sure that
> setting is correct before basing an access rule on this function.

## Adding your own functions

The library is a plain Perl module without any dependency on the portal or
handler internals: to add a function, drop it in
`lib/Lemonldap/NG/Common/CustomFunctions.pm`, add its name to the list
returned by `functions()`, and declare it in `customFunctions`.

Keep the functions
[Safe jail](https://lemonldap-ng.org/documentation/latest/safejail.html)
compatible if you can — a function shared with the jail runs outside of it,
so only the code you write _in_ the rules and macros is restricted.

## Tests

```bash
node mcp/cli.js test custom-functions
```

`t/01-CustomFunctions.t` unit-tests the functions (UUID vectors are
cross-checked against Python's `uuid.uuid5`);
`t/02-CustomFunctions-Jail.t` checks the whole integration path — library
loaded through `require`, functions declared in `customFunctions`, then
called from a compiled rule, with and without the Safe jail.
