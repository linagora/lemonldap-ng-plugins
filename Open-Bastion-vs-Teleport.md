# Open-Bastion vs Teleport Community Edition

Comparaison de positionnement entre **Open-Bastion** (LemonLDAP::NG + plugins +
modules PAM/NSS) et **Teleport Community Edition** (édition open source / AGPLv3,
auto-hébergée).

> **Convention de lecture**
> Le tableau compare à **Teleport Community Edition**. Quand une fonctionnalité
> n'existe que dans l'édition payante (Teleport **Enterprise** ou **Cloud**),
> elle est marquée **💰 Enterprise**.
>
> | Symbole       | Sens                                            |
> | ------------- | ----------------------------------------------- |
> | ✅            | Inclus / open, sans coût de licence             |
> | 💰 Enterprise | Nécessite Teleport Enterprise ou Cloud (payant) |
> | ➖            | Hors périmètre / non couvert                    |
>
> _Le découpage des éditions Teleport évolue : vérifier la grille en vigueur sur
> goteleport.com avant toute décision d'achat. Document de positionnement, daté
> de juin 2026._

---

## 1. En bref

- **Open-Bastion** : greffe légère sur l'existant. Le **SSO LemonLDAP::NG**
  décide la politique (accès SSH et `sudo`), des **modules PAM/NSS natifs**
  l'appliquent sur chaque hôte via l'`sshd` standard. Périmètre concentré sur
  **l'accès SSH/`sudo` Linux**. **100 % open (GPL), aucune fonction bridée**, le
  SSO OIDC/SAML/CAS est inclus.
- **Teleport Community** : plateforme « identity-native » multi-protocole (SSH,
  Kubernetes, bases de données, RDP/Windows, apps web). Control plane Go
  (Auth + Proxy) et agents. Très complet, mais **plusieurs fonctions de sécurité
  et de gouvernance clés sont réservées à l'édition payante** — à commencer par
  le **SSO OIDC/SAML**.

La différence structurante : Open-Bastion **délègue l'identité à un SSO que vous
exploitez déjà** et reste minimaliste ; Teleport **apporte sa propre plateforme**
mais facture l'intégration SSO d'entreprise et la gouvernance avancée.

---

## 2. Architecture

| Aspect                  | Open-Bastion                                         | Teleport Community                                            |
| ----------------------- | ---------------------------------------------------- | ------------------------------------------------------------- |
| Cerveau de la politique | LemonLDAP::NG (IAM/SSO existant)                     | Teleport Auth Service (CA + RBAC + audit)                     |
| Point d'application     | Modules **PAM/NSS** sur l'hôte + `sshd` de la distro | **Agent `teleport`** par ressource (ou « agentless » OpenSSH) |
| Ingress                 | Bastion qui ré-origine la connexion                  | Proxy Service (ingress unique, reverse tunnels)               |
| Démon sur les hôtes     | **Aucun** (juste les libs PAM/NSS)                   | Agent à opérer (sauf mode agentless)                          |
| Client utilisateur      | `ssh` standard + `ob-ssh-cert`                       | `tsh` pour l'expérience complète                              |
| Empreinte               | Modules C + portail Perl, réutilise le LLNG en place | Control plane à exploiter (ou Cloud managé 💰)                |

---

## 3. Tableau de fonctionnalités

### Accès et identité

| Fonctionnalité                                     | Open-Bastion                                                | Teleport Community            |
| -------------------------------------------------- | ----------------------------------------------------------- | ----------------------------- |
| Certificats SSH courts (OpenSSH)                   | ✅ `ssh-ca` signe ; `sshd` standard via `TrustedUserCAKeys` | ✅ CA user/host, certs courts |
| Login CLI / headless                               | ✅ OIDC Device Authorization Grant                          | ✅ `tsh login`                |
| SSO **GitHub**                                     | ✅ (LLNG, comme n'importe quel OIDC)                        | ✅                            |
| SSO **OIDC** générique                             | ✅ (cœur de LLNG, gratuit)                                  | **💰 Enterprise**             |
| SSO **SAML**                                       | ✅ (LLNG est IdP SAML)                                      | **💰 Enterprise**             |
| 2FA / MFA                                          | ✅ (TOTP, WebAuthn… via LLNG)                               | ✅ (MFA par session incluse)  |
| Self-service onboarding (signer sa clé au portail) | ✅                                                          | ✅ (`tsh`)                    |
| Offboarding immédiat (fermer le compte SSO)        | ✅                                                          | ✅                            |
| Comptes de service / « backup » partout            | ✅ (service accounts, avec/sans `sudo`)                     | ✅ (rôles + Machine ID)       |

### Enforcement Linux

| Fonctionnalité                                     | Open-Bastion                                                                                                     | Teleport Community                                                                                                      |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Décider l'accès SSH par appartenance de groupe SSO | ✅                                                                                                               | ✅ (RBAC `logins`)                                                                                                      |
| Contrôle de **`sudo`**                             | ✅ **gaté en live à chaque appel** via `pam_openbastion` → `/pam/authorize` (compte statique **ou** provisionné) | ⚠️ Partiel : `host_sudoers` **seulement** lors du provisioning auto du compte ; pas de gate runtime sur compte statique |
| Provisioning de comptes Unix (NSS)                 | ✅ résout les utilisateurs SSO, crée le home au 1er login                                                        | ✅ (host user creation)                                                                                                 |
| Résilience hors-ligne (panne SSO)                  | ✅ cache local **chiffré**                                                                                       | ⚠️ dépend du cache de l'agent / disponibilité du control plane                                                          |

### Bastion, enregistrement et anti-contournement

| Fonctionnalité                                                   | Open-Bastion                                                                       | Teleport Community                                                                                                                                                            |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Enregistrement de session                                        | ✅ côté bastion, store root-only inviolable                                        | ✅ (proxy ou nœud)                                                                                                                                                            |
| Backends **refusent toute connexion non vouchée** par le bastion | ✅ **par conception** (le backend exige un voucher de bastion, pas un simple cert) | ➖ Non : la confiance porte sur le **certificat**, pas sur le chemin ; un cert valide est accepté en direct                                                                   |
| **Port-forward autorisé sans ouvrir de pivot hors-enregistreur** | ✅ le backend rejette le tunnel non vouché → forward légitime possible sans bypass | ➖ Non : le port-forward **est** un vecteur de contournement ; seule parade = le **désactiver globalement** (on/off, raffiné `local`/`remote` depuis v15) ou isoler le réseau |
| Audit d'événement « port forward demandé »                       | ✅                                                                                 | ✅ (événement audité ; contenu tunnelé non enregistré)                                                                                                                        |
| Sessions modérées / multi-approbation                            | ➖ (constructible côté LLNG)                                                       | **💰 Enterprise** (Moderated Sessions)                                                                                                                                        |
| Relecture / playback UI riche, stockage S3                       | ⚠️ enregistrement simple, inviolable                                               | ✅ (UI de relecture, S3, enhanced recording BPF)                                                                                                                              |

### Gouvernance et accès avancé

| Fonctionnalité                                                                 | Open-Bastion                                                                              | Teleport Community                                                                                                             |
| ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Authentification ≠ autorisation** (une clé/cert valide ne donne pas l'accès) | ✅ l'autorisation est vérifiée **en direct**, séparément de l'authentification            | ➖ l'autorisation est **encodée dans le certificat** émis                                                                      |
| **Propagation instantanée** d'un retrait/réduction de droits                   | ✅ ré-évaluée à **chaque accès et chaque `sudo`** ; sortir du groupe SSO = refus immédiat | ⚠️ effectif à l'**expiration du cert** (TTL, souvent quelques h), ou via **Lock** explicite (inclus Community, near-real-time) |
| Changement de rôle propagé vite (groupes SSO)                                  | ✅ (immédiat à l'accès suivant)                                                           | ⚠️ à la **réémission** du cert (re-login/renew), pas rétroactif                                                                |
| **Just-in-time / Access Requests** (escalade temporisée, double validation)    | ➖ (constructible dans LLNG)                                                              | **💰 Enterprise**                                                                                                              |
| **Access Lists** (revue d'accès périodique)                                    | ➖                                                                                        | **💰 Enterprise**                                                                                                              |
| **Device Trust** (exiger un appareil enrôlé)                                   | ➖                                                                                        | **💰 Enterprise**                                                                                                              |
| Verrouillage d'identité / sessions (locks)                                     | ⚠️ via fermeture/àJour SSO                                                                | ✅ (lock API incluse)                                                                                                          |
| **Access Monitoring / Identity Security (graph)**                              | ➖                                                                                        | **💰 Enterprise / Cloud**                                                                                                      |

### Périmètre des ressources

| Ressource                  | Open-Bastion                                    | Teleport Community |
| -------------------------- | ----------------------------------------------- | ------------------ |
| SSH Linux + `sudo`         | ✅ (cœur)                                       | ✅                 |
| Apps **web** (SSO HTTP)    | ✅ via LLNG (axe séparé : WebSSO/reverse-proxy) | ✅ (App Access)    |
| **Kubernetes**             | ➖                                              | ✅                 |
| **Bases de données**       | ➖                                              | ✅                 |
| **RDP / Windows desktops** | ➖                                              | ✅                 |
| Console / CLI **AWS**      | ➖                                              | ✅                 |

### Conformité, déploiement, exploitation

| Fonctionnalité                        | Open-Bastion                                                        | Teleport Community                |
| ------------------------------------- | ------------------------------------------------------------------- | --------------------------------- |
| Déploiement de flotte en une commande | ✅ `ob-builder` → rôle Ansible ou installeur shell auto-extractible | ✅ (installeurs, Helm, Terraform) |
| Paquets natifs                        | ✅ Debian **et** RPM EL9/EL10                                       | ✅ (deb/rpm, conteneurs)          |
| CA dans un **HSM**                    | ⚠️ selon intégration LLNG                                           | **💰 Enterprise**                 |
| Builds **FIPS / FedRAMP**             | ➖                                                                  | **💰 Enterprise**                 |
| Intégrations Okta / JAMF, etc.        | ➖ (LLNG fait IdP, pas ces connecteurs SaaS)                        | **💰 Enterprise**                 |
| Hébergement managé (SaaS)             | ➖ (auto-hébergé)                                                   | **💰 Teleport Cloud**             |
| Support commercial                    | Linagora (services)                                                 | **💰 Enterprise / Cloud**         |

---

## 4. Les points qui font la différence

### 4.1 Authentification ≠ autorisation, et propagation instantanée

C'est sans doute la distinction la plus structurante.

- **Open-Bastion** : la clé (ou le certificat SSO) sert à **authentifier** —
  prouver _qui_ tu es. Mais **l'autorisation d'accès est une décision séparée**,
  prise **en direct** par `pam_openbastion` qui interroge LLNG (`/pam/authorize`)
  à **chaque connexion et chaque `sudo`**. Conséquence : **une clé encore valide
  ne donne aucun accès** si l'autorisation a été retirée. Sortir un utilisateur
  d'un groupe (ou fermer son compte) dans le SSO prend effet **à l'accès suivant**,
  sans révoquer ni faire expirer quoi que ce soit, sans action explicite — le
  cache chiffré couvrant les pannes SSO.

- **Teleport Community** : l'autorisation est **figée dans le certificat court**
  au moment de son émission (rôles → `logins`/principals, TTL). Tant que le cert
  est valide, ses droits le suivent. Donc :
  - réduire les droits d'un rôle n'affecte **pas** un cert déjà émis : il faut
    attendre l'**expiration** (TTL, souvent quelques heures) ou un **re-login** ;
  - pour couper **immédiatement**, il faut poser un **Lock** (mécanisme inclus en
    Community, appliqué en near-real-time tant que les composants sont en ligne) —
    mais c'est une **action explicite et grossière** (verrouiller l'utilisateur,
    le rôle, un login…), pas une ré-évaluation continue de la politique.

En résumé : chez Open-Bastion la révocation est un **effet de bord gratuit** du
modèle (authZ recalculée à chaque fois) ; chez Teleport elle suppose soit
d'attendre le TTL, soit de déclencher un verrou.

### 4.2 Contrôle de `sudo`

- **Open-Bastion** : `pam_openbastion` interroge LLNG (`/pam/authorize`) **à chaque
  invocation de `sudo`**, sur compte statique **comme** provisionné, avec cache
  chiffré pour les pannes SSO. Le `sudoers` local n'est plus la source de vérité.
- **Teleport Community** : contrôle **quel utilisateur Unix** tu deviens (`logins`
  RBAC). `sudo` n'est piloté que **lorsque Teleport provisionne le compte** à la
  volée, en générant un fichier `host_sudoers` retiré à la déconnexion. Sur un
  **compte statique préexistant**, `sudo` reste celui du `/etc/sudoers` local —
  non gaté. C'est une **génération de sudoers**, pas un appel IdP runtime.

### 4.3 Les backends refusent-ils les connexions hors bastion ?

- **Open-Bastion** : **oui, par conception**. Le backend n'accepte qu'une
  connexion **vouchée par le bastion** (cert éphémère signé LLNG, ré-origination).
  Un cert utilisateur seul ne permet pas d'atteindre le backend.
- **Teleport Community** : **non intrinsèquement**. L'enforcement repose sur le
  **certificat, pas sur le chemin**. Un nœud OpenSSH (`TrustedUserCAKeys`) accepte
  tout cert Teleport valide, qu'il transite par le Proxy ou non. Forcer le passage
  par le Proxy relève de la **topologie réseau** (nœuds en reverse-tunnel only,
  `sshd` natif verrouillé manuellement), pas d'une garantie native.

### 4.4 Port-forward sans contournement de l'enregistreur

- **Open-Bastion** : peut **autoriser le port-forward** tout en empêchant son usage
  pour atteindre un backend hors-enregistreur — parce que **le backend rejette le
  tunnel non vouché**. Le contournement est fermé **côté destination**, l'usage
  légitime reste ouvert.
- **Teleport Community** : le port-forward **est** un vecteur de contournement de
  l'enregistreur (le trafic tunnelé est opaque ; un cert valide tunnelé est honoré
  en direct). La seule parade est l'**interdiction globale** du port-forwarding
  (booléen, raffiné `local`/`remote` depuis la v15) ou l'isolation réseau —
  jamais « autorisé mais sans pivot ». Teleport **audite l'événement** de forward,
  mais **n'enregistre pas le contenu** tunnelé.

---

## 5. Licence et coût

|                                                                  | Open-Bastion                                                  | Teleport Community                                               |
| ---------------------------------------------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------- |
| Licence                                                          | **GPL / open**, sans bridage                                  | **AGPLv3** (Community)                                           |
| SSO OIDC/SAML                                                    | **Inclus gratuitement**                                       | **💰 Enterprise**                                                |
| Gouvernance (JIT, Access Lists, Device Trust, sessions modérées) | Hors périmètre, mais **constructible dans LLNG sans surcoût** | **💰 Enterprise**                                                |
| HSM, FIPS/FedRAMP                                                | Selon intégration                                             | **💰 Enterprise**                                                |
| Modèle économique                                                | Open + services (Linagora)                                    | Open (Community) **+ licences** pour l'entreprise / Cloud managé |

**À retenir** : sur le périmètre SSH/`sudo`, les fonctions de sécurité
quotidiennes d'Open-Bastion (SSO OIDC/SAML, sudo gaté, anti-contournement) sont
**gratuites** ; chez Teleport, **le SSO d'entreprise lui-même** bascule en
Enterprise payant, ainsi que la gouvernance avancée.

---

## 6. Quand choisir quoi

**Choisir Teleport** si :

- parc **hétérogène** (Kubernetes, bases de données, RDP, apps web) à couvrir par
  un seul outil ;
- besoin de **JIT / Access Requests / Device Trust / sessions modérées** clé-en-main
  (et budget Enterprise) ;
- envie d'un **éditeur unique** avec support et hébergement managé.

**Choisir Open-Bastion** si :

- le besoin réel est **l'accès SSH/`sudo` Linux** maîtrisé de bout en bout ;
- vous exploitez déjà (ou voulez) un **SSO LemonLDAP::NG**, et tenez à ce que le
  **SSO OIDC/SAML reste gratuit** ;
- vous voulez une **garantie d'anti-contournement** de l'enregistreur (port-forward
  autorisable sans pivot, backends qui rejettent le hors-bastion) ;
- vous voulez une **révocation instantanée** : authentification ≠ autorisation, donc
  retirer un droit (ou un compte) dans le SSO coupe l'accès à l'opération suivante,
  même si la clé/le cert reste techniquement valide ;
- empreinte minimale sur **OpenSSH standard**, sans agent ni control plane dédié ;
- préférence **open / GPL / souveraineté EU**, sans fonctionnalité bridée.

---

## 7. Réserves

- Le périmètre Community vs Enterprise de Teleport **évolue** ; les marquages 💰
  reflètent l'état connu à la date du document et doivent être confirmés sur la
  grille officielle.
- Certaines lignes « ➖ » d'Open-Bastion (JIT, Access Lists…) sont **réalisables
  côté LLNG** par configuration, mais ne sont pas livrées clé-en-main : à
  distinguer d'une absence pure.
- Les comportements Teleport décrits (`host_sudoers`, confiance au certificat,
  port-forwarding) dépendent du **mode de déploiement** (agent vs agentless,
  reverse-tunnel, verrouillage du `sshd` natif).
