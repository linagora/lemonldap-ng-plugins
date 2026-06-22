#!/bin/bash
# Build a signed yum/dnf repository from the .rpm files produced by
# rpm/build-rpms.sh. RPM counterpart of debian/build-repo.sh.
#
# All packages are noarch and carry no EL-version-specific dependency, so a
# single repository serves both EL9 and EL10. The repository metadata
# (repomd.xml) is signed with the same GPG key as the Debian Release file;
# the generated .repo enables repo_gpgcheck to verify it (the exact parallel
# of the signed Debian Release).
set -e

RPMS_DIR="${1:?Usage: $0 <rpms-dir> <output-dir>}"
OUTPUT_DIR="${2:?Usage: $0 <rpms-dir> <output-dir>}"

RPMS_DIR="$(cd "$RPMS_DIR" && pwd)"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

# Public base URL of the published repo (GitHub Pages). Used only to render the
# ready-to-paste .repo file and index.html; falls back to a placeholder.
REPO_URL="${REPO_URL:-}"

echo "Copying .rpm files..."
cp "${RPMS_DIR}/"*.rpm "${OUTPUT_DIR}/"

echo "Generating repository metadata (createrepo_c)..."
createrepo_c --general-compress-type=gz "${OUTPUT_DIR}"

echo "Signing repomd.xml..."
gpg --batch --yes --armor \
  ${GPG_PASSPHRASE:+--passphrase "$GPG_PASSPHRASE" --pinentry-mode loopback} \
  --detach-sign -o "${OUTPUT_DIR}/repodata/repomd.xml.asc" \
  "${OUTPUT_DIR}/repodata/repomd.xml"

# Export the public key alongside the repo so dnf can fetch it.
gpg --armor --export > "${OUTPUT_DIR}/store-key.asc" 2>/dev/null || true

GPGKEY_URL="${REPO_URL%/}/store-key.asc"
BASEURL="${REPO_URL%/}"
[ -n "$REPO_URL" ] || { GPGKEY_URL="REPLACE_WITH_REPO_URL/store-key.asc"; BASEURL="REPLACE_WITH_REPO_URL"; }

echo "Generating linagora-llng-plugins.repo..."
cat > "${OUTPUT_DIR}/linagora-llng-plugins.repo" <<EOF
[linagora-llng-plugins]
name=Linagora LemonLDAP::NG Plugins (EL\$releasever)
baseurl=${BASEURL}
enabled=1
# Metadata is GPG-signed (mirrors the signed Debian Release).
repo_gpgcheck=1
# Individual packages are not signed in this repo; rely on repo_gpgcheck.
gpgcheck=0
gpgkey=${GPGKEY_URL}
EOF

echo "Generating index.html..."
PKG_ROWS=""
while IFS= read -r rpm; do
  base="$(basename "$rpm")"
  PKG_ROWS="${PKG_ROWS}<tr><td><a href=\"${base}\">${base}</a></td></tr>"
done < <(find "${OUTPUT_DIR}" -maxdepth 1 -name '*.rpm' | sort)

cat > "${OUTPUT_DIR}/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Linagora LemonLDAP::NG Plugins — RPM Repository (EL9/EL10)</title>
  <style>body{font-family:sans-serif;max-width:740px;margin:2em auto;padding:0 1em}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px 10px;text-align:left}th{background:#f5f5f5}pre{background:#f4f4f4;padding:1em;overflow-x:auto}code{font-size:.9em}</style>
</head>
<body>
  <h1>RPM Repository (EL9 &amp; EL10)</h1>
  <p>dnf/yum repository for
  <a href="https://lemonldap-ng.org">LemonLDAP::NG</a> plugins.
  All packages are <code>noarch</code> and serve RHEL/Rocky/AlmaLinux 9 &amp; 10.</p>
  <h2>Setup</h2>
  <pre>sudo curl -fsSL ${BASEURL}/linagora-llng-plugins.repo \\
  -o /etc/yum.repos.d/linagora-llng-plugins.repo

sudo dnf install linagora-lemonldap-ng-store</pre>
  <h2>Packages</h2>
  <table>
    <thead><tr><th>Package</th></tr></thead>
    <tbody>${PKG_ROWS}</tbody>
  </table>
  <p><small><a href="../">Back to store</a></small></p>
</body>
</html>
EOF

echo "RPM repository built at ${OUTPUT_DIR}/"
echo ""
echo "Structure:"
find "$OUTPUT_DIR" -type f | sort
