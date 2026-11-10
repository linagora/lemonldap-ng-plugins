# Upgrading

What an operator has to do, or check, before deploying a given release. Only
releases that need something are listed; anything not mentioned here upgrades
by replacing the files.

The full list of changes is in [CHANGELOG.md](CHANGELOG.md) — this document is
the subset that requires a decision.

## Unreleased

`mail-autodiscover` now accepts only a dot-atom local part and a DNS domain in
the `email` parameter. An address with a quoted local part or RFC 822 comments
is replaced by `%EMAILADDRESS%`, as any other invalid value already was.
Non-ASCII addresses and single-label domains such as `user@localhost` are
also replaced.

`oidc-ciba` now applies `oidcRPMetaDataOptionsRule` and the scope rules
(`oidcRPMetaDataScopeRules`, `oidcServiceAllowOnlyDeclaredScopes`, and the
`oidcResolveScope` hooks) on every CIBA path. A rule based on
`$_oidc_grant_type` must accept the `ciba` value, for example:

```perl
$_oidc_grant_type =~ /^(?:authorizationcode|ciba)$/
```

Public clients (`oidcRPMetaDataOptionsPublic`) are now refused on both
backchannel routes.

## v0.7.1

Mostly input validation: the plugins below refuse what they used to accept.
Check these points before upgrading; the rest upgrades by replacing the files.

1. **`matrix-token-exchange` now sends every Matrix server through
   `LWPx::ParanoidAgent`**, listed or not. An internal Matrix server must be
   added to `oidcRPMetaDataOptionsTokenXMatrixInternalHosts` on its Relying
   Party, and a portal that reaches Matrix only through an HTTP proxy can no
   longer use listed servers (`LWPx::ParanoidAgent` ignores
   `lwpOpts`/`env_proxy`). New runtime dependency
   `liblwpx-paranoidagent-perl`. See the
   [plugin README](plugins/matrix/README.md#upgrading-from-07x).
2. **`pacc` native registration now needs dynamic registration.**
   `paccAllowNativeClientRegistration` only filters clients; it no longer
   opens the registration endpoint. Set
   `oidcServiceAllowDynamicRegistration = 1` (or `2` for public clients), and
   note that `paccAllowNativeClientRegistration = 0` now really refuses
   loopback clients. See the [README](plugins/pacc/README.md).
3. **`oidc-ciba` only accepts user hints it can verify.** `login_hint` and
   the `id_token_hint` `sub` must resolve through the local user backends,
   `login_hint_token` is refused, and `id_token_hint` needs an asymmetric
   signature, this issuer and the requesting client as audience. The RP
   `sub` must be the login attribute. With `Auth = Choice`, set
   `oidcServiceCibaChoice`. See the
   [README](plugins/oidc-ciba/README.md#validation).
4. **`oidc-federation` fetches are blocked on private addresses** unless
   `oidcFederationAllowPrivateHosts = 1`, and the new
   `oidcFederationFetchTimeout`, `oidcFederationResolutionTimeout` and
   `oidcFederationCacheTTL` bound and cache resolutions. Trust chains are
   stricter (statement links, `exp`, configured anchor keys) and federated
   registration goes through `oidcRegisterClient`. New runtime dependency
   `liblwpx-paranoidagent-perl`. See the
   [README](plugins/oidc-federation/README.md#trust-chain-resolution).
5. **`json-file` ignores runtime attributes declared in the user file**
   (`_*`, `groups`, `hGroups`, `ipAddr`, `UA`, `authenticationLevel`); use
   the `groups` object for group membership. A malformed file or group now
   disables the backend at init instead of dying on each login. See the
   [README](plugins/json-file/README.md#json-file-format).
6. **`reports` CSV files changed**: every field is quoted, and values
   starting with `=`, `+`, `-`, `@`, a tab or a CR are prefixed with `'`.
   Consumers must accept quoting and that apostrophe. See the
   [README](plugins/reports/README.md#csv-format).
7. **`custom-functions.uuid()` hashes unflagged Latin-1 strings as UTF-8**,
   so UUIDs computed from such input change. ASCII, UTF-8 bytes and decoded
   characters are unchanged. See the
   [README](plugins/custom-functions/README.md#uuidvalue-namespace).

## v0.7.0

`matrix-token-exchange` refuses exchanges it used to accept, and adds an
option. Check the points below before upgrading.

1. **An empty `oidcRPMetaDataOptionsTokenXAuthorizedMatrix` now accepts no
   Matrix server**, even when the RP is also the caller. Fill the list for
   every RP that must accept the exchange.
2. **A public Relying Party can no longer be the target of an exchange.** Give
   the Matrix server a confidential client (with a secret), or keep the
   exchange disabled for that RP.
3. **An exchange towards another Relying Party needs the caller in its
   `oidcRPMetaDataOptionsTokenXAuthorizedRP`**, as for LLNG token exchange.
   Add the caller to every target RP that accepted cross-RP exchanges before.
4. **`oidcRPMetaDataOptionsTokenXMatrixUser=mail` changes the user lookup**
   from `user` to `user@domain.tld`, so `LDAPFilter` must also match `mail`.
   Without this option, only list Matrix servers whose users share the `uid`
   namespace of the user database.
5. **`*` is only honoured with the mail mapping**, and only safe when each
   mail domain's Matrix server is run by whoever runs its mailboxes. A public
   Matrix server with open registration on `domain.tld` would get tokens for
   every `user@domain.tld`.
6. **New runtime dependency `LWPx::ParanoidAgent`** (Debian:
   `liblwpx-paranoidagent-perl`), used for servers accepted through `*`.

## v0.6.0

The security audit of the open-bastion SSO chain (ssh-ca, pam-access, the
device grant). **This round changes behaviour operators may rely on.**

> **`pam-access` 0.6.0 requires open-bastion 0.7.0 or later** — note 6.

> **Start here.** Note 10 is the only change in this release that can take a
> fleet down, and it does so silently, hours after the switch is flipped.

1. **SSH CA administration denies until configured.** `/ssh/admin`,
   `/ssh/certs` and `/ssh/revoke` answer 403 while `sshCaAdminRule` is unset;
   set it (e.g. `inGroup('ssh-admins')`). Per-user endpoints are unaffected.
2. **RSA below 2048 bits and `ssh-dss` are no longer signed** (HTTP 400). Add
   `dss` to `sshCaAllowedKeyTypes` or lower `sshCaMinKeyBits` to keep them.
   FIDO2 `sk-*` keys, previously refused, now sign.
3. **The PAM scope is matched exactly** (`pam`, `pam:server`): an RP granted
   `pam-prod` or `x-pam` loses `/pam/*`. Check `oidcRPMetaDataScopeRules`.
4. **Malformed ssh-ca inputs answer 400** instead of being coerced:
   `validity_days`, `limit`/`offset`, revocation `reason`.
5. **The device-grant audit records carry `user_code_hash`**, not `user_code`,
   wherever the code is still live. The value is `hmac_sha256_hex(code, key)`,
   so it cannot be recomputed from a code without the portal secret. SIEM
   rules keyed on that field need updating. The `pamAccessRequireFingerprint`
   refusal also has its own codes now, `PAM_AUTH_SSH_FP_REQUIRED` /
   `PAM_AUTHZ_SSH_FP_REQUIRED`, instead of sharing the malformed ones.
6. **`/pam/bastion-token` is gone** (deprecated, superseded by
   `/pam/bastion-cert`). Any caller still using it gets a 404; its
   `pamAccessBastionJwtTtl` and `pamAccessBastionMaxSeenAge` settings are
   removed. Its `probe: true` mode — the only way for a server to read its own
   portal-assigned id — is replaced by `POST /pam/whoami`; `ob-bastion-id`
   needs its URL changed and nothing else, the `bastion_id` field is kept.
   Two fields of the probe response do not come back: `probe: true`, and a
   `server_group` that used to be present unconditionally (`/pam/whoami`
   returns it only when `pamAccessServerGroups` maps the caller). Neither is
   read by `ob-bastion-id`, which takes `.bastion_id` alone; they show up only
   in its `--verbose` dump of the raw body.
7. **A bastion voucher minted without an SSH fingerprint now lives 15 minutes**
   instead of 12 hours (`pamAccessBastionVoucherUnboundTtl`), and
   `/pam/bastion-cert` refuses to mint when `pamAccessBastionCertPinSourceAddress`
   is set but the observed address is unusable.

8. **`/ssh/sign` is rate-limited and capped** (`sshCaSignMaxPerHour` 20/h,
   `sshCaMaxCertsPerUser` 20). Deployments that legitimately sign more must
   raise them or set them to `0`. Re-signing a key you already hold does not
   count against the certificate quota.
9. **The ssh-ca POST routes require `Content-Type: application/json`** and
   refuse a foreign `Origin`. Clients already sending the documented content
   type are unaffected.
10. **Do not set `pamAccessRequestSigningMode` to `required` yet.** The gate
    covers all six `/pam/*` endpoints; the open-bastion client signs two of
    them. `required` would refuse `/pam/heartbeat`, which is how every
    enrolled host renews its access token — invisible when you flip the
    switch, then the whole fleet at once when those tokens expire. Stay on
    `optional` until the client signs heartbeat and bastion-cert.

Not breaking, but opt-in and worth doing: `pamAccessAllowedRps` binds `/pam/*`
to your PAM relying parties and stops a host from declaring itself a bastion
(#50). Empty by default; a warning says so once per worker.

Not breaking, but worth knowing: enabling `pamAccessHeartbeatRequired` makes
`/pam/heartbeat` an operational dependency; the new device-grant bounds are
Manager validations that only bite on the next save, with runtime floors
meanwhile.

## v0.5.1

- **Minimum supported LemonLDAP::NG is 2.23.2.**
