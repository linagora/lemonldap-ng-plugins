# Matrix plugin

This plugin allow a Matrix client to exchange its Matrix `access_token` to
get a LLNG `access_token`. Files:

- [Lemonldap::NG::Portal::Plugins::MatrixTokenExchange](./MatrixTokenExchange.pm) with its dependency [Lemonldap::NG::Common::Matrix](./Matrix.pm)
- A [patch for the manager](./manager.patch) _(remember to [rebuild other files](../UpdateManager.md))_

# Use case

Even if Matrix can be connected to [Lemonldap::NG](https://lemonldap-ng.org)
via [OpenID-Connect](https://lemonldap-ng.org/documentation/latest/applications/matrix.html),
the Matrix server uses federation just to authorize the client to access to an account _(it create it on the fly if needed)_,
then it losts the link with LLNG _(except for [Back-Channel-Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html))_.

Thus if you develop a Matrix client that needs to access to another OIDC resource server of your SSO space,
you need to have a valid `access_token`. This is the goal of this plugin.

# How to use it

[Lemonldap::NG::Portal::Plugins::MatrixTokenExchange](./MatrixTokenExchange.pm)
use the same logic than [LLNG OpenID Connect Token Exchange](https://lemonldap-ng.org/documentation/latest/oidctokenexchange)
but with Matrix `access_token`. You just have to authorize a list of [Matrix servers][^1] by setting them in
`oidcRPMetaDataOptionsTokenXAuthorizedMatrix` _(space separated)_ in each OICD Relying Party
that allows this exchange. Then the software client just have to exchange its
Matrix `access_token` using "token" endpoint. Example with [curl](https://manpages.debian.org/unstable/curl/curl.1.en.html):

```shell
curl -XPOST
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
--data-urlencode 'client_id=rpid' \
--data-urlencode 'subject_token=sid-bbb-aaa-ccc' \
--data-urlencode 'subject_issuer=m.org' \
--data-urlencode 'scope=openid profile email' \
--data-urlencode 'audience=rpid' \
https://lemon-portal/oauth2/token
```

If client isn't public, add `--basic -u 'client_id:password'`

[^1]: In [Matrix specs](https://spec.matrix.org/latest/), a "Matrix server" is the domain part of a Matrix address, not the hostname of the server.
This plugin follows the [specification](https://spec.matrix.org/v1.14/server-server-api/#server-discovery) to find the server.
