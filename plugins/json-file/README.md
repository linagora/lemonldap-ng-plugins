# JsonFile - JSON file-based user backend

**Development/test only - NOT for production use.**

Authentication and UserDB backend that loads user accounts from a JSON file.
Useful for local development, integration testing, and CI/CD pipelines.

Inherits from the Demo backend, so all Demo features (FindUser, groups, etc.)
work out of the box.

## Installation

### Via the LLNG store

If your LemonLDAP::NG installation supports the plugin store:

```bash
lemonldap-ng-store install json-file
```

### Manual installation

Copy the modules into LemonLDAP::NG's portal library path:

```bash
cp lib/Lemonldap/NG/Portal/Auth/JsonFile.pm \
   /usr/share/perl5/Lemonldap/NG/Portal/Auth/
cp lib/Lemonldap/NG/Portal/UserDB/JsonFile.pm \
   /usr/share/perl5/Lemonldap/NG/Portal/UserDB/
```

To add "JsonFile" to the Manager dropdowns, install the override and
rebuild the manager files:

```bash
cp manager-overrides/json-file.json /etc/lemonldap-ng/manager-plugins.d/
llng-build-manager-files --plugins-dir=/etc/lemonldap-ng/manager-plugins.d
```

## Configuration

### 1. Set the environment variable

Point `LLNG_JSONUSERS` to your JSON file:

```bash
export LLNG_JSONUSERS=/path/to/users.json
```

For Apache, add to your portal vhost configuration:

```apache
SetEnv LLNG_JSONUSERS /etc/lemonldap-ng/users.json
```

For nginx with FastCGI:

```nginx
fastcgi_param LLNG_JSONUSERS /etc/lemonldap-ng/users.json;
```

### 2. Configure LemonLDAP::NG

In the Manager, set:

- **Authentication** → `JsonFile`
- **User database** → `JsonFile`

Or in `lemonldap-ng.ini`:

```ini
[portal]
authentication = JsonFile
userDB         = JsonFile
```

### 3. Exported variables

Configure `exportedVars` and/or `demoExportedVars` in the Manager to map
JSON attributes to session variables. The default `exportedVars` mapping
(`uid`, `cn`, `mail`) works if your JSON users contain those fields.

## JSON file format

```json
{
  "users": {
    "jdoe": {
      "password": "secret123",
      "uid": "jdoe",
      "cn": "John Doe",
      "mail": "jdoe@example.com",
      "department": "Engineering"
    },
    "asmith": {
      "password": "test456",
      "uid": "asmith",
      "cn": "Alice Smith",
      "mail": "asmith@example.com",
      "department": "Marketing"
    }
  },
  "groups": {
    "admins": ["jdoe"],
    "users": ["jdoe", "asmith"],
    "marketing": ["asmith"]
  }
}
```

### Fields

- **users** (required): Object mapping usernames to their attributes.
  - **password**: Plain-text password. If omitted, defaults to the username
    (same as Demo behavior).
  - **uid**: User identifier. If omitted, defaults to the username key.
  - Any other fields are available as session attributes via `exportedVars`
    / `demoExportedVars`.
- **groups** (optional): Object mapping group names to arrays of member
  usernames. Populates `groups` and `hGroups` session variables.

## Differences from the Demo backend

| Feature | Demo | JsonFile |
|---------|------|----------|
| User accounts | Hardcoded (dwho, rtyler, msmith) | Loaded from JSON file |
| Passwords | Always equal to username | Defined per user in JSON |
| Attributes | Fixed set | Any attributes in JSON |
| Groups | Hardcoded | Defined in JSON |
| Reload | Requires restart | Reloads on config reload |

## Keycloak-inspired usage

Inspired by Keycloak's realm-export.json, you can define a complete test
realm in a single JSON file and version-control it alongside your project:

```
my-project/
  docker-compose.yml
  llng-users.json        ← your test users
  src/
  tests/
```

```yaml
# docker-compose.yml
services:
  portal:
    image: yadd/lemonldap-ng-portal
    environment:
      - LLNG_JSONUSERS=/users.json
    volumes:
      - ./llng-users.json:/users.json:ro
```
