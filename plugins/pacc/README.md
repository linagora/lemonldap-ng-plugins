# PACC - Provider Automatic Configuration for Clients

This plugin implements [PACC (draft-ietf-mailmaint-pacc)](https://datatracker.ietf.org/doc/draft-ietf-mailmaint-pacc/)
for LemonLDAP::NG, enabling automatic mail client configuration through a
standardized JSON endpoint.

## Features

- **`/.well-known/pacc.json` endpoint**: returns configuration for mail servers
  (IMAP, SMTP, JMAP, CalDAV, CardDAV) with OAuth2 issuer information
- **Native client registration**: allows OIDC dynamic registration for native
  apps with loopback redirect URIs (localhost, 127.0.0.1, [::1]), even when
  global dynamic registration is disabled
- **Public client support**: honors `token_endpoint_auth_method: "none"` in
  registration requests for clients that cannot store a secret (relies on PKCE)

## Requirements

- LemonLDAP::NG >= 2.23.0 (requires `oidcGotRegistrationRequest` and
  `oidcGenerateRegistrationResponse` hooks)

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
| `paccAllowNativeClientRegistration` | 1       | Allow dynamic registration for native clients with loopback URIs |
| `paccStrictNativeClientOnly`        | 1       | Reject non-native client registrations in strict mode            |

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
- **Loopback URIs**: only `localhost`, `127.0.0.1`, and `[::1]` are accepted
  per [RFC 8252](https://tools.ietf.org/html/rfc8252)

## See Also

- [PACC specification (draft-ietf-mailmaint-pacc)](https://datatracker.ietf.org/doc/draft-ietf-mailmaint-pacc/)
- [RFC 8252 - OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252)
