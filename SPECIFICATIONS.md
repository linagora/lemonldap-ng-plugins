# Specifications implemented by Lemonldap::NG

This page lists the standards, RFCs and specifications implemented by
[Lemonldap::NG](https://lemonldap-ng.org/).

Each row has two columns:

- **Core** — implementation shipped with LLNG upstream (✅).
- **LNG plugin** — implementation provided by this repository's [store](https://linagora.github.io/lemonldap-ng-plugins/) 🧩.
- 🧪 marks a specification that is still in draft state.

Specifications are grouped by protocol family:

1. [OpenID Connect & OAuth 2.0](#1-openid-connect--oauth-20)
2. [SAML 2.0](#2-saml-20)
3. [CAS](#3-cas)
4. [Other protocols](#4-other-protocols)

---

## 1. OpenID Connect & OAuth 2.0

### 1.1 OpenID Connect

| Specification                                                                                                             | Core | LNG plugin                                      |
| ------------------------------------------------------------------------------------------------------------------------- | ---- | ----------------------------------------------- |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)                                          | ✅   |                                                 |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)                                | ✅   |                                                 |
| [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)           | ✅   |                                                 |
| [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)                         | ✅   |                                                 |
| [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)                    | ✅   |                                                 |
| [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)                    | ✅   |                                                 |
| [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)                  | ✅   |                                                 |
| [OpenID Connect Native SSO for Mobile Apps 1.0](https://openid.net/specs/openid-connect-native-sso-1_0.html)              | ✅   |                                                 |
| [OpenID Connect CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) |      | 🧩 [`oidc-ciba`](plugins/oidc-ciba)             |
| [OpenID Connect Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)                                      |      | 🧩 [`oidc-federation`](plugins/oidc-federation) |

### 1.2 OAuth 2.0 framework and extensions

| Specification                                                                                                | Core | LNG plugin                                                                                                                           |
| ------------------------------------------------------------------------------------------------------------ | ---- | ------------------------------------------------------------------------------------------------------------------------------------ |
| [OAuth 2.0 Authorization Framework (RFC 6749)](https://www.rfc-editor.org/rfc/rfc6749)                       | ✅   |                                                                                                                                      |
| [OAuth 2.0 Bearer Token Usage (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750)                            | ✅   |                                                                                                                                      |
| [OAuth 2.0 Token Revocation (RFC 7009)](https://www.rfc-editor.org/rfc/rfc7009)                              | ✅   |                                                                                                                                      |
| [OAuth 2.0 Assertion Framework for Client Authentication (RFC 7521)](https://www.rfc-editor.org/rfc/rfc7521) | ✅   |                                                                                                                                      |
| [JWT Profile for OAuth 2.0 Client Authentication (RFC 7523)](https://www.rfc-editor.org/rfc/rfc7523)         | ✅   |                                                                                                                                      |
| [OAuth 2.0 PKCE (RFC 7636)](https://www.rfc-editor.org/rfc/rfc7636)                                          | ✅   |                                                                                                                                      |
| [OAuth 2.0 Token Introspection (RFC 7662)](https://www.rfc-editor.org/rfc/rfc7662)                           | ✅   |                                                                                                                                      |
| [OAuth 2.0 Device Authorization Grant (RFC 8628)](https://www.rfc-editor.org/rfc/rfc8628)                    |      | 🧩 [`oidc-device-authorization`](plugins/oidc-device-authorization) + [`oidc-device-organization`](plugins/oidc-device-organization) |
| [OAuth 2.0 Token Exchange (RFC 8693)](https://www.rfc-editor.org/rfc/rfc8693)                                | ✅   |                                                                                                                                      |
| [Pushed Authorization Requests — PAR (RFC 9126)](https://www.rfc-editor.org/rfc/rfc9126)                     |      | 🧩 [`oidc-par`](plugins/oidc-par)                                                                                                    |
| [OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)](https://www.rfc-editor.org/rfc/rfc9207)    | ✅   |                                                                                                                                      |
| [JWT Secured Authorization Response Mode — JARM](https://openid.net/specs/oauth-v2-jarm.html)                |      | 🧩 [`oidc-jarm`](plugins/oidc-jarm)                                                                                                  |
| [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700)                | ✅   |                                                                                                                                      |
| [JWT Response for OAuth 2.0 Token Introspection (RFC 9701)](https://www.rfc-editor.org/rfc/rfc9701)          | ✅   |                                                                                                                                      |

### 1.3 JOSE (JSON Object Signing and Encryption)

Used by OIDC and the OAuth 2.0 JWT-based extensions above.

| Specification                                                                  | Core |
| ------------------------------------------------------------------------------ | ---- |
| [JSON Web Signature — JWS (RFC 7515)](https://www.rfc-editor.org/rfc/rfc7515)  | ✅   |
| [JSON Web Encryption — JWE (RFC 7516)](https://www.rfc-editor.org/rfc/rfc7516) | ✅   |
| [JSON Web Key — JWK (RFC 7517)](https://www.rfc-editor.org/rfc/rfc7517)        | ✅   |
| [JSON Web Algorithms — JWA (RFC 7518)](https://www.rfc-editor.org/rfc/rfc7518) | ✅   |
| [JSON Web Token — JWT (RFC 7519)](https://www.rfc-editor.org/rfc/rfc7519)      | ✅   |

---

## 2. SAML 2.0

| Specification                                                                       | Core |
| ----------------------------------------------------------------------------------- | ---- |
| [SAML v2.0 Core](https://www.oasis-open.org/standard/saml/) — IdP, SP, proxy        | ✅   |
| SAML 2.0 Web Browser SSO Profile (HTTP-Redirect, HTTP-POST, HTTP-Artifact bindings) | ✅   |
| SAML 2.0 Single Logout Profile (SLO)                                                | ✅   |
| SAML 2.0 Metadata                                                                   | ✅   |

---

## 3. CAS

| Specification                                                                                                                                       | Core |
| --------------------------------------------------------------------------------------------------------------------------------------------------- | ---- |
| [CAS Protocol 1.0 — `validate`](https://apereo.github.io/cas/development/protocol/CAS-Protocol-Specification.html)                                  | ✅   |
| [CAS Protocol 2.0 — `serviceValidate`, `proxyValidate`, `proxy`](https://apereo.github.io/cas/development/protocol/CAS-Protocol-Specification.html) | ✅   |
| [CAS Protocol 3.0 — attributes, `p3/serviceValidate`](https://apereo.github.io/cas/development/protocol/CAS-Protocol-Specification.html)            | ✅   |
| CAS Single Sign-Out (front-channel + back-channel)                                                                                                  | ✅   |

---

## 4. Other protocols

### 4.1 Authentication backends

| Specification                                                                                | Core |
| -------------------------------------------------------------------------------------------- | ---- |
| [LDAP v3 (RFC 4511)](https://www.rfc-editor.org/rfc/rfc4511) — authentication / user backend | ✅   |
| [Radius (RFC 2865)](https://www.rfc-editor.org/rfc/rfc2865) — authentication backend         | ✅   |
| [Kerberos / SPNEGO (RFC 4559)](https://www.rfc-editor.org/rfc/rfc4559)                       | ✅   |

### 4.2 Second factors

| Specification                                                                                                         | Core |
| --------------------------------------------------------------------------------------------------------------------- | ---- |
| [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/) / [FIDO2](https://fidoalliance.org/fido2/)                      | ✅   |
| [TOTP (RFC 6238)](https://www.rfc-editor.org/rfc/rfc6238) / [HOTP (RFC 4226)](https://www.rfc-editor.org/rfc/rfc4226) | ✅   |

### 4.3 Application integrations

| Specification / Integration                                                                                                                                                  | Core | LNG plugin                                          |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | --------------------------------------------------- |
| [PACC — Provider Automatic Configuration for Clients (draft-ietf-mailmaint-pacc)](https://datatracker.ietf.org/doc/draft-ietf-mailmaint-pacc/)                               |      | 🧪 🧩 [`pacc`](plugins/pacc)                        |
| [Microsoft Autodiscover v2 for SMTP/IMAP](https://learn.microsoft.com/en-us/exchange/client-developer/web-service-reference/autodiscover-web-service-reference-for-exchange) |      | 🧩 [`mail-autodiscover`](plugins/mail-autodiscover) |
| [Thunderbird Mail Autoconfig](https://wiki.mozilla.org/Thunderbird:Autoconfiguration)                                                                                        |      | 🧩 [`mail-autodiscover`](plugins/mail-autodiscover) |
| [Matrix Client-Server API — federation token validation](https://spec.matrix.org/latest/server-server-api/)                                                                  |      | 🧩 [`matrix`](plugins/matrix)                       |
| [OpenSSH Certificate Authority](https://man.openbsd.org/ssh-keygen.1) — user certificates signed via SSO                                                                     |      | 🧩 [`ssh-ca`](plugins/ssh-ca)                       |
| [PAM — Pluggable Authentication Modules](https://www.kernel.org/pub/linux/libs/pam/) — token-based access for SSH/sudo                                                       |      | 🧩 [`pam-access`](plugins/pam-access)               |

---

## Contributing

Something missing? Please open an [issue](https://github.com/linagora/lemonldap-ng-plugins/issues)
or submit a pull request.
