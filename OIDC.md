<p align="center">
  <a href="https://linagora.com"><img src="linagora.png" alt="LINAGORA" width="300"></a>
</p>

# OpenID Connect & OAuth 2.0 in LemonLDAP::NG

This document is a narrative companion to [`SPECIFICATIONS.md`](SPECIFICATIONS.md) (the per-RFC checklist). It explains, in plain prose:

1. [What you get out of the box](#1-what-you-get-out-of-the-box) — the OIDC Provider and OIDC Client capabilities shipped with LemonLDAP::NG core.
2. [What this store adds](#2-what-this-store-adds) — the plugins published in this repository, organized by use case rather than by RFC number.
3. [FAPI 2.0 in LemonLDAP::NG](#3-fapi-20-in-lemonldapng) — what FAPI 2.0 mandates, what's covered today, what's still pending.
4. [Decision guide](#4-decision-guide) — "I need X, what do I install?".
5. [Working examples](#5-working-examples) — config snippets that combine the pieces.

---

## 1. What you get out of the box

LemonLDAP::NG (LLNG) ships a complete OAuth 2.0 / OpenID Connect stack on both sides of the wire.

### 1.1 As an OpenID Provider (OP)

> Endpoint root is configurable; defaults shown below.

| Capability                                 | Endpoint                                      | Notes                                                                    |
| ------------------------------------------ | --------------------------------------------- | ------------------------------------------------------------------------ |
| Authorization endpoint                     | `/oauth2/authorize`                           | All standard OIDC parameters, `acr_values` and `max_age` honored.        |
| Token endpoint                             | `/oauth2/token`                               | `authorization_code`, `refresh_token`, `client_credentials`, `password`. |
| UserInfo                                   | `/oauth2/userinfo`                            | Bearer-protected, JSON or signed/encrypted JWT response.                 |
| Introspection (RFC 7662 + RFC 9701)        | `/oauth2/introspect`                          | JSON or `application/token-introspection+jwt`.                           |
| Revocation (RFC 7009)                      | `/oauth2/revoke`                              | Access tokens and refresh tokens.                                        |
| JWKS                                       | `/oauth2/jwks`                                | RSA, EC, AES — managed via the Manager.                                  |
| Discovery                                  | `/.well-known/openid-configuration`           | All RFC 8414 fields.                                                     |
| Dynamic Client Registration (RFC 7591)     | `/oauth2/register`                            | Filter / mutate via `oidcGotRegistrationRequest` / `oidcRegisterClient`. |
| Front-Channel Logout                       | `frontchannel_logout_uri` per RP              |                                                                          |
| Back-Channel Logout                        | `backchannel_logout_uri` per RP               | Signed logout token.                                                     |
| Session Management 1.0                     | `/oauth2/checksession`                        |                                                                          |
| RP-Initiated Logout                        | `/oauth2/end_session`                         |                                                                          |
| `iss` in authorization response (RFC 9207) | _automatic_                                   |                                                                          |
| Native SSO for Mobile Apps                 | _per-RP option_                               |                                                                          |
| Token Exchange (RFC 8693)                  | `/oauth2/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` | Hook-driven (`oidcGotTokenExchange`); request typically carries `subject_token`, `subject_token_type` and optional `audience` / `resource`. |
| Per-RP scope rules                         | `oidcRPMetaDataScopeRules` (Perl, sandboxed)  | Same plumbing this store extends for RAR rules and RS rules.             |

### 1.2 Authentication & client metadata

| Feature                                              | Status                   |
| ---------------------------------------------------- | ------------------------ |
| `client_secret_basic` / `client_secret_post`         | ✅                       |
| `client_secret_jwt`                                  | ✅                       |
| `private_key_jwt` (RFC 7521 + RFC 7523)              | ✅                       |
| `tls_client_auth` / `self_signed_tls_client_auth`    | ⏳ pending upstream LLNG release ([issue #3442](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/3442)) |
| PKCE (RFC 7636), enforced via `RequirePKCE` per RP   | ✅                       |
| ID-token signing: HS\*, RS\*, ES\*, PS\*             | ✅                       |
| ID-token / userinfo / introspection encryption (JWE) | ✅                       |
| Refresh-token rotation                               | ✅ per-RP option         |
| Offline access (`offline_access` scope)              | ✅                       |

### 1.3 As an OpenID Connect Relying Party (RP)

LLNG can also _consume_ OIDC for itself (e.g., delegating authentication to another OP). Capabilities:

| Capability                               | Notes                                          |
| ---------------------------------------- | ---------------------------------------------- |
| Authorization-code flow (with PKCE)      |                                                |
| Userinfo lookup                          | Via the OP's `/userinfo`.                      |
| ID-token signature verification          | Auto-fetches JWKS from the OP's discovery URL. |
| ID-token encryption decryption           |                                                |
| Front- and back-channel logout receiving |                                                |
| `acr_values` and `max_age` propagation   |                                                |
| Auto-discovery from `.well-known`        | Or static metadata file.                       |
| Multiple OPs on a single LLNG portal     | Choice screen / per-vhost / per-rule.          |

### 1.4 Plugin extension points

The LLNG core exposes a stable hook system that this store relies on. Some hooks added recently and used heavily by the plugins below:

- `oidcGotRequest` — at /authorize, before any further processing.
- `oidcGotTokenRequest` — at /token, before grant-type dispatch (LLNG ≥ 2.23).
- `oidcGenerateCode`, `oidcGenerateRefreshToken`, `oidcGenerateAccessToken`.
- `oidcGenerateTokenResponse` — fires for both `authorization_code` and `refresh_token` grants since 2.23.
- `oidcGenerateIntrospectionResponse`, `oidcGenerateMetadata`, `oidcResolveScope`.
- `oidcGotOnlineRefresh` / `oidcGotOfflineRefresh`.

The full list, with versions and example handlers, is in the upstream `doc/sources/admin/hooks.rst` page of LemonLDAP::NG.

---

## 2. What this store adds

The plugins are grouped by use case below. Each is a self-contained `.deb`-installable bundle (`sudo lemonldap-ng-store install <name>`); they don't depend on each other unless explicitly noted. See each plugin's own README for the per-option configuration table.

### 2.1 OAuth 2.0 / OIDC extensions for fine-grained authorization

| Plugin                                                         | Spec                                                                             | What it does in one sentence                                                                                                                                             |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [`oidc-rar`](plugins/oidc-rar)                                 | [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) (Rich Authorization Requests) | Lets clients request very fine-grained, structured authorizations via the `authorization_details` parameter (e.g., "transfer 100 € to IBAN X") instead of opaque scopes. |
| [`oidc-resource-indicators`](plugins/oidc-resource-indicators) | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) (Resource Indicators)         | Lets clients name target Resource Server(s) via the `resource` parameter; the OP binds the issued token to that RS audience and evaluates per-RS scope rules.            |
| [`oidc-grant-management`](plugins/oidc-grant-management)       | [FAPI Grant Management](https://openid.net/specs/fapi-grant-management.html)     | Introduces grants as durable, queryable, modifiable, revocable records — supports `create` / `update` / `replace` actions and a RESTful `/oauth2/grants/{id}` endpoint.  |
| [`oidc-scope-applications`](plugins/oidc-scope-applications)   | _LLNG-specific_                                                                  | Per-application scope visibility / filtering on the consent screen.                                                                                                      |
| [`oidc-global-scopes`](plugins/oidc-global-scopes)             | _LLNG-specific_                                                                  | Define scopes once at the service level and reuse across RPs.                                                                                                            |

### 2.2 Authorization-request transport hardening

| Plugin                           | Spec                                                                                          | What it does                                                                                                                    |
| -------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| [`oidc-par`](plugins/oidc-par)   | [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126) (Pushed Authorization Requests)            | Adds `/oauth2/par` so clients push authorize parameters back-channel and receive a `request_uri`. Also a client-side companion. |
| [`oidc-jar`](plugins/oidc-jar)   | [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101) (JWT Secured Authorization Request)        | Lets clients sign their authorize request in a JWT (`request=...`).                                                             |
| [`oidc-jarm`](plugins/oidc-jarm) | [JARM](https://openid.net/specs/oauth-v2-jarm.html) (JWT-Secured Authorization Response Mode) | Lets the OP return the authorize response as a signed JWT (`response_mode=jwt`).                                                |

### 2.3 Authentication context for Resource Servers

| Plugin                                       | Spec                                                                                            | What it does                                                                                                                                                      |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`oidc-acr-claims`](plugins/oidc-acr-claims) | [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470) (Step-Up Authentication Challenge — AS side) | Emits the `acr` and `auth_time` claims on JWT access tokens, so an RS can decide if the user's auth context is sufficient and otherwise emit a step-up challenge. |

### 2.4 Alternative grants

| Plugin                                                           | Spec                                                                                                            | What it does                                                                  |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| [`oidc-ciba`](plugins/oidc-ciba)                                 | [OIDC CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) | Client-Initiated Backchannel Authentication (push/poll/ping modes).           |
| [`oidc-device-authorization`](plugins/oidc-device-authorization) | [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)                                                              | Device Authorization Grant for input-constrained clients (TVs, CLIs).         |
| [`oidc-device-organization`](plugins/oidc-device-organization)   | _Companion_                                                                                                     | Organization-aware device enrollment (used with `oidc-device-authorization`). |

### 2.5 Federation

| Plugin                                       | Spec                                                                                 | What it does                                                                                     |
| -------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| [`oidc-federation`](plugins/oidc-federation) | [OpenID Connect Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) | Trust chain validation, automatic trust establishment between OPs and RPs through trust anchors. |

---

## 3. FAPI 2.0 in LemonLDAP::NG

[FAPI 2.0](https://openid.net/specs/fapi-2_0-security-profile.html) is the OpenID Foundation's profile for high-stakes deployments — **open banking (PSD2 / PSD3), open insurance, open energy, eHealth, government identity**. It is a _profile_, not a single spec: it picks specific RFCs and constrains how they must be combined.

### 3.1 The Security Profile mandates

| FAPI 2.0 requirement                                                      | LLNG status                                                                                                                    |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Authorization code grant only** (no implicit, no hybrid)                | ✅ Configurable per RP — disable `oidcServiceAllowImplicitFlow` and `oidcServiceAllowHybridFlow`.                              |
| **PKCE S256 mandatory**                                                   | ✅ Core; enforce per RP via `oidcRPMetaDataOptionsRequirePKCE`.                                                                |
| **PAR mandatory**                                                         | 🧩 [`oidc-par`](plugins/oidc-par); enforce per RP via `oidcRPMetaDataOptionsPAR=required`.                                     |
| **Pushed `request_uri` only** (no other `request_uri` schemes)            | 🧩 with PAR `required` mode.                                                                                                   |
| **Resource Indicators (RFC 8707)**                                        | 🧩 [`oidc-resource-indicators`](plugins/oidc-resource-indicators).                                                             |
| **`iss` in authz response (RFC 9207)**                                    | ✅ Core.                                                                                                                       |
| **Sender-constrained access tokens — mTLS path (RFC 8705)**               | ⏳ Pending upstream LLNG release ([issue #3442](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/3442)).                |
| **Sender-constrained access tokens — DPoP path (RFC 9449)**               | ⏳ Pending: needs a small core hook (`oidcParseAuthorization` or equivalent) to override the Bearer-only Authorization parser. |
| **Strong client authentication** (`private_key_jwt` or `tls_client_auth`) | ✅ `private_key_jwt` in core; `tls_client_auth` lands with [issue #3442](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/3442). |

### 3.2 The Message Signing Profile mandates

The Message Signing Profile is FAPI 2.0's stricter sibling that mandates JWT-signed exchanges everywhere.

| Requirement                                    | LLNG status                         |
| ---------------------------------------------- | ----------------------------------- |
| **JAR mandatory** (signed authorize request)   | 🧩 [`oidc-jar`](plugins/oidc-jar)   |
| **JARM mandatory** (signed authorize response) | 🧩 [`oidc-jarm`](plugins/oidc-jarm) |
| **JWT-secured introspection (RFC 9701)**       | ✅ Core, since 2.23.                |
| **Signed logout token** (back-channel logout)  | ✅ Core.                            |
| **ID Token signed with non-`none` alg**        | ✅ Core default.                    |

### 3.3 What's missing

For a complete FAPI 2.0 alignment in LLNG today, the gap is:

- **DPoP (RFC 9449)** — the only feature with no implementation path yet. It needs a tiny core change first (a hook on the Authorization-header parser), after which the plugin itself is ~300-500 lines. mTLS is the alternative sender-constraint, so deployments that go all-mTLS are FAPI 2.0-aligned once [issue #3442](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/3442) lands.

- **`acr_values_supported` discovery field** — informative only; trivial follow-up via `oidcGenerateMetadata`.

Everything else — PAR, JAR, JARM, RAR, Resource Indicators, RFC 9207, RFC 9701, ACR claims on AT, Grant Management — is shipped (core or plugin) today.

### 3.4 Useful "FAPI-adjacent" pieces also in scope

These are not strictly required by FAPI 2.0 but are commonly demanded alongside:

- **RAR** ([`oidc-rar`](plugins/oidc-rar)) — needed by the FAPI Message Signing profile _examples_, and required by some PSD2 ASPSP profiles.
- **Grant Management** ([`oidc-grant-management`](plugins/oidc-grant-management)) — explicitly referenced by the PSD3 draft (2026) for the 180-day consent renewal mechanism.
- **Step-Up auth claims** ([`oidc-acr-claims`](plugins/oidc-acr-claims)) — for fine-grained operations where the RS wants to require fresh / strong auth.

### 3.5 How to deploy a FAPI 2.0-aligned LLNG today (mTLS path)

Once mTLS lands upstream ([issue #3442](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/3442)) and assuming you want the _Security Profile_ (not the Message Signing one):

1. Install `oidc-par` and `oidc-resource-indicators` from this store.
2. Configure your RPs:

   | Option                                                       | Value                            |
   | ------------------------------------------------------------ | -------------------------------- |
   | `oidcRPMetaDataOptionsRequirePKCE`                           | `1`                              |
   | `oidcRPMetaDataOptionsPAR`                                   | `required`                       |
   | `oidcRPMetaDataOptionsAuthMethod`                            | `tls_client_auth`                |
   | `oidcRPMetaDataOptionsTLSClientCertificateBoundAccessTokens` | `1`                              |
   | `oidcRPMetaDataOptionsAllowImplicitFlow`                     | `0`                              |
   | `oidcRPMetaDataOptionsAllowHybridFlow`                       | `0`                              |
   | `oidcRPMetaDataOptionsEnableRI`                              | `1` (on each Resource Server RP) |

3. Disable `oidcServiceAllowImplicitFlow` and `oidcServiceAllowHybridFlow` at the service level.

4. Configure your reverse proxy (nginx / apache) to validate the client TLS certificate and pass it to LLNG via the standard headers.

5. Add `oidc-jar` + `oidc-jarm` if you target the _Message Signing_ variant.

6. Add `oidc-rar` if your business domain needs structured authorization beyond scopes.

7. Add `oidc-grant-management` if you have to expose user-facing "connected apps" management or PSD2 90-day renewal semantics.

The DPoP path is the same minus mTLS, plus the `oidc-dpop` plugin (planned, not yet shipped).

---

## 4. Decision guide

Quick lookup if you know what you need.

| Use case                                                                                          | What to install / enable                                                     |
| ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Plain SSO with OIDC                                                                               | Just core LLNG, RP configuration in the Manager.                             |
| Mobile / SPA client                                                                               | Core + `RequirePKCE` per RP.                                                 |
| TV / CLI / device flow                                                                            | `oidc-device-authorization`.                                                 |
| Decoupled auth (authenticate on phone, app on laptop)                                             | `oidc-ciba`.                                                                 |
| Hide authorize parameters from the URL bar / referrer                                             | `oidc-par`.                                                                  |
| Sign authorize request                                                                            | `oidc-jar`.                                                                  |
| Sign authorize response                                                                           | `oidc-jarm`.                                                                 |
| Bind tokens to a specific Resource Server (multi-API setups)                                      | `oidc-resource-indicators`.                                                  |
| Fine-grained, transaction-specific authorizations (PSD2 payment, healthcare order, etc.)          | `oidc-rar`.                                                                  |
| User-facing dashboard "connected apps", PSD2 / PSD3 consent renewal, single-call grant revocation | `oidc-grant-management`.                                                     |
| Resource Server needs to enforce step-up / max-age policies                                       | `oidc-acr-claims` (AS side; RS-side challenge logic is on the RS).           |
| Federation between OPs and RPs through trust anchors                                              | `oidc-federation`.                                                           |
| FAPI 2.0 Security Profile (PSD2-grade)                                                            | upstream mTLS ([#3442](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/3442)) + `oidc-par` + `oidc-resource-indicators` + RP config above. |
| FAPI 2.0 Message Signing Profile                                                                  | _the above_ + `oidc-jar` + `oidc-jarm`.                                      |

---

## 5. Working examples

### 5.1 Open banking AISP — minimal config

```ini
# Service level
oidcServiceAllowImplicitFlow             = 0
oidcServiceAllowHybridFlow               = 0

# Per-RP (the AISP fintech client)
oidcRPMetaDataOptionsClientID            = aisp-12345
oidcRPMetaDataOptionsRequirePKCE         = 1
oidcRPMetaDataOptionsPAR                 = required
oidcRPMetaDataOptionsAuthMethod          = tls_client_auth     # once mTLS lands
oidcRPMetaDataOptionsAccessTokenJWT      = 1
oidcRPMetaDataOptionsAuthorizationDetailsEnabled = 1           # RAR: structured authz
oidcRPMetaDataOptionsAuthorizationDetailsTypes   = payment_initiation,account_information
oidcRPMetaDataOptionsGrantManagement     = allowed              # FAPI Grant Management
oidcRPMetaDataOptionsAcrClaims           = 1                    # acr + auth_time on AT
oidcRPMetaDataOptionsAllowOffline        = 1

# Per-RP rules: only allow payments above 1000 € when the user has done strong auth
oidcRPMetaDataAuthorizationDetailsRules:
  payment_initiation: |
    $detail->{instructedAmount}->{amount} <= 1000
    or $authenticationLevel >= 4
```

### 5.2 Multi-API SaaS (Resource Indicators)

```ini
# RP A: the client app
oidcRPMetaDataOptionsClientID = my-spa-client
# RP B: API service "billing"
oidcRPMetaDataOptionsClientID = billing-api
oidcRPMetaDataOptionsEnableRI = 1
oidcRPMetaDataOptionsRIIdentifier = https://api.example.com/billing

# Per-RS scope rules
oidcRPMetaDataRIScopes:
  read:invoices: Read invoices
  write:invoices: Modify invoices
oidcRPMetaDataRIScopeRules:
  read:invoices: 1
  write:invoices: '$groups =~ /\bbilling-admin\b/'
```

The client then asks for `?resource=https://api.example.com/billing&scope=read:invoices`; the AT issued has `aud` containing `billing-api` (or its identifier), and the API can validate based on `aud` + `scope`.

### 5.3 Step-up for sensitive operations

```ini
# RP (the API)
oidcRPMetaDataOptionsAcrClaims = 1
oidcRPMetaDataOptionsAccessTokenJWT = 1

# Service-level ACR mapping
oidcServiceMetaDataAuthnContext:
  urn:llng:loa:basic:    1
  urn:llng:loa:elevated: 3
```

The API receives an AT with `acr=urn:llng:loa:basic, auth_time=...`. For a high-stakes endpoint, the RS returns:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
    acr_values="urn:llng:loa:elevated",
    max_age=120
```

The client re-runs `/oauth2/authorize?acr_values=urn:llng:loa:elevated&max_age=120&...`, the OP forces step-up, the new AT carries the higher `acr`, the API call succeeds.

---

## See also

- [`SPECIFICATIONS.md`](SPECIFICATIONS.md) — the per-RFC checklist, all protocols.
- [Upstream LLNG OIDC documentation](https://lemonldap-ng.org/documentation/latest/idpopenidconnect.html) — operator-facing guide for the OP side.
- [Upstream LLNG hooks reference](https://lemonldap-ng.org/documentation/latest/hooks) — the hook system every plugin in this store relies on.
