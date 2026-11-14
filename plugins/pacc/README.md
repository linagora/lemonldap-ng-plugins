# PACC - Provider Automatic Configuration for Clients

This plugin implements [PACC (draft-ietf-mailmaint-pacc)](https://datatracker.ietf.org/doc/draft-ietf-mailmaint-pacc/)
for LemonLDAP::NG, enabling automatic mail client configuration through a
standardized JSON endpoint.

## Features

- **`/.well-known/pacc.json` endpoint**: returns configuration for mail servers
  (IMAP, SMTP, JMAP, CalDAV, CardDAV) with OAuth2 issuer information
- **Native client registration**: allows OIDC dynamic registration for native
  apps with loopback redirect URIs (localhost, 127.0.0.1, [::1]) when dynamic
  registration is enabled. Public clients need
  `oidcServiceAllowDynamicRegistration = 2`.
- **Any port on loopback redirect URIs**: a native app listens on a port
  chosen by the system at each login, so a declared loopback redirect URI
  (`http://127.0.0.1/`, `http://[::1]/`, `http://localhost/`) also accepts
  the same URI on any port, as required by
  [RFC 8252 section 7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3).
  Applies to every RP, declared in the Manager or registered dynamically.
- **Public client support**: the core honours
  `token_endpoint_auth_method: "none"` when
  `oidcServiceAllowDynamicRegistration = 2`; PACC only filters which clients
  may register

## Requirements

- LemonLDAP::NG >= 2.23.2 (requires the `oidcGotRegistrationRequest` hook)

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.24.0)_ or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```bash
sudo lemonldap-ng-store install pacc
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-plugins.d/`, add `::Plugins::PACC` to
`customPlugins`, and run `llng-build-manager-files`.

## Configuration

In the Manager, go to **OpenID Connect Service** > **PACC Configuration**:

### Main Parameters

| Parameter                           | Default | Description                                                      |
| ----------------------------------- | ------- | ---------------------------------------------------------------- |
| `paccEnabled`                       | 0       | Enable the PACC endpoint                                         |
| `paccAllowNativeClientRegistration` | 1       | Allow loopback native clients; when disabled, loopback registrations are refused (dynamic registration must be enabled) |
| `paccStrictNativeClientOnly`        | 1       | Reject non-native client registrations in strict mode            |
| `paccLoopbackAnyPort`               | 1       | Accept any port on a declared loopback redirect URI (RFC 8252 §7.3) |

### IMAP Settings

| Parameter          | Default                          | Description                              |
| ------------------ | -------------------------------- | ---------------------------------------- |
| `paccImapEnabled`  | 0                                | Enable IMAP in PACC response             |
| `paccImapHostname` |                                  | IMAP server hostname                     |
| `paccImapPort`     | 993                              | IMAP server port                         |
| `paccImapAuth`     | `OAuth2 sasl-SCRAM-SHA-256-PLUS` | Authentication methods (space-separated) |

### SMTP Settings

| Parameter          | Default  | Description                              |
| ------------------ | -------- | ---------------------------------------- |
| `paccSmtpEnabled`  | 0        | Enable SMTP in PACC response             |
| `paccSmtpHostname` |          | SMTP server hostname                     |
| `paccSmtpPort`     | 465      | SMTP server port                         |
| `paccSmtpAuth`     | `OAuth2` | Authentication methods (space-separated) |

### Other Protocols

| Parameter            | Default | Description         |
| -------------------- | ------- | ------------------- |
| `paccJmapEnabled`    | 0       | Enable JMAP         |
| `paccJmapUrl`        |         | JMAP service URL    |
| `paccCalDavEnabled`  | 0       | Enable CalDAV       |
| `paccCalDavUrl`      |         | CalDAV service URL  |
| `paccCardDavEnabled` | 0       | Enable CardDAV      |
| `paccCardDavUrl`     |         | CardDAV service URL |

## Example Response

```bash
curl https://auth.example.com/.well-known/pacc.json
```

```json
{
  "servers": {
    "imap": {
      "hostname": "imap.example.com",
      "port": 993,
      "authentication": ["OAuth2", "sasl-SCRAM-SHA-256-PLUS"]
    },
    "smtp": {
      "hostname": "smtp.example.com",
      "port": 465,
      "authentication": ["OAuth2"]
    }
  },
  "oAuth2": {
    "issuer": "https://auth.example.com"
  }
}
```

## Security Considerations

- **Strict Mode**: when `paccStrictNativeClientOnly` is enabled, registration
  requests with non-loopback URIs are rejected
- **PKCE**: public clients should always use PKCE for authorization
- **Loopback ports**: with `paccLoopbackAnyPort`, only the port may differ
  from a declared loopback redirect URI: scheme, host (no switch between
  `127.0.0.1`, `[::1]` and `localhost`), path and query must match exactly.
  This applies to the authorization endpoint only, not to
  `post_logout_redirect_uri`. Require PKCE on such RPs: another local
  process listening on a different port could otherwise receive the code
- **Loopback URIs**: only `localhost`, `127.0.0.1`, and `[::1]` are accepted
  per [RFC 8252](https://tools.ietf.org/html/rfc8252)

## See Also

- [PACC specification (draft-ietf-mailmaint-pacc)](https://datatracker.ietf.org/doc/draft-ietf-mailmaint-pacc/)
- [RFC 8252 - OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252)
