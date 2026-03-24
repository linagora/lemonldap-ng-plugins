# Matrix Token Exchange

This plugin allows a Matrix client to exchange its Matrix `access_token` to
get a LLNG `access_token`.

## Files

- `lib/Lemonldap/NG/Portal/Plugins/MatrixTokenExchange.pm` — Portal plugin
- `lib/Lemonldap/NG/Common/Matrix.pm` — Matrix library (server resolution + token validation)
- `manager-overrides/matrix.json` — Manager extension (attribute, ctree, translations)
- `plugin.json` — Plugin metadata

## Use case

Even if Matrix can be connected to [Lemonldap::NG](https://lemonldap-ng.org)
via [OpenID-Connect](https://lemonldap-ng.org/documentation/latest/applications/matrix.html),
the Matrix server uses federation just to authorize the client to access to an account _(it create it on the fly if needed)_,
then it losts the link with LLNG _(except for [Back-Channel-Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html))_.

Thus if you develop a Matrix client that needs to access to another OIDC resource server of your SSO space,
you need to have a valid `access_token`. This is the goal of this plugin.

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```
sudo lemonldap-ng-store install matrix-token-exchange --activate
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/` into `/etc/lemonldap-ng/manager-plugins.d/`, add `::Plugins::MatrixTokenExchange` to `customPlugins`, and run `llng-build-manager-files`.

## How to use it

This plugin uses the same logic as [LLNG OpenID Connect Token Exchange](https://lemonldap-ng.org/documentation/latest/oidctokenexchange)
but with Matrix `access_token`. You just have to authorize a list of [Matrix servers][^1] by setting them in
`oidcRPMetaDataOptionsTokenXAuthorizedMatrix` _(space separated)_ in each OICD Relying Party
that allows this exchange. Then the software client just have to exchange its
Matrix "federation token" using "token" endpoint. Example with [curl](https://manpages.debian.org/unstable/curl/curl.1.en.html):

### 1. First get a [federation token](https://spec.matrix.org/v1.14/client-server-api/#openid)

```Shell
$ curl -XPOST -d '{}' https://matrix-server.domain.tld/_matrix/client/v3/user/@user:domain.tld/openid/request_token
```

Response looks like:

```json
{
  "access_token": "SomeT0kenHere",
  "expires_in": 3600,
  "matrix_server_name": "domain.tld",
  "token_type": "Bearer"
}
```

### 2. use it to get the access*token to access to the OIDC Relying Party "rpid" *(which has `domain.tld` inside its `oidcRPMetaDataOptionsTokenXAuthorizedMatrix` list)\_

```Shell
$ curl -XPOST \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
--data-urlencode 'client_id=rpid' \
--data-urlencode 'subject_token=SomeT0kenHere' \
--data-urlencode 'subject_issuer=domain.tld' \
--data-urlencode 'scope=openid profile email' \
--data-urlencode 'audience=rpid' \
https://lemon-portal.domain.tld/oauth2/token
```

If client isn't public, add `--basic -u 'client_id:password'`

## Prerequisites

- LLNG version 2.20.0 or later
- Perl modules: `Net::DNS`, `Regexp::Common`

[^1]:
    In [Matrix specs](https://spec.matrix.org/latest/), a "Matrix server" is the domain part of a Matrix address, not the hostname of the server.
    This plugin follows the [specification](https://spec.matrix.org/v1.14/server-server-api/#server-discovery) to find the server.
