# Upgrading

What an operator has to do, or check, before deploying a given release. Only
releases that need something are listed; anything not mentioned here upgrades
by replacing the files.

The full list of changes is in [CHANGELOG.md](CHANGELOG.md) — this document is
the subset that requires a decision.

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
