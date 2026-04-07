#!/bin/bash
set -e

DEBS_DIR="${1:?Usage: $0 <debs-dir> <output-dir>}"
OUTPUT_DIR="${2:?Usage: $0 <debs-dir> <output-dir>}"

DEBS_DIR="$(cd "$DEBS_DIR" && pwd)"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

POOL_DIR="${OUTPUT_DIR}/pool"
DISTS_DIR="${OUTPUT_DIR}/dists/stable/main/binary-all"
RELEASE_DIR="${OUTPUT_DIR}/dists/stable"

mkdir -p "$POOL_DIR" "$DISTS_DIR" "$RELEASE_DIR"

echo "Copying .deb files to pool/..."
cp "${DEBS_DIR}/"*.deb "${POOL_DIR}/"

echo "Generating Packages index..."
cd "$OUTPUT_DIR"
dpkg-scanpackages --arch all pool/ > "${DISTS_DIR}/Packages"
gzip -9 -k -f "${DISTS_DIR}/Packages"

echo "Generating Release file..."
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin="Linagora" \
  -o APT::FTPArchive::Release::Label="Linagora LemonLDAP::NG Plugins" \
  -o APT::FTPArchive::Release::Suite="stable" \
  -o APT::FTPArchive::Release::Codename="stable" \
  -o APT::FTPArchive::Release::Components="main" \
  -o APT::FTPArchive::Release::Architectures="all" \
  release "${RELEASE_DIR}" > "${RELEASE_DIR}/Release"

echo "Signing Release file..."
gpg --batch --yes --armor \
  ${GPG_PASSPHRASE:+--passphrase "$GPG_PASSPHRASE" --pinentry-mode loopback} \
  --detach-sign -o "${RELEASE_DIR}/Release.gpg" "${RELEASE_DIR}/Release"

gpg --batch --yes \
  ${GPG_PASSPHRASE:+--passphrase "$GPG_PASSPHRASE" --pinentry-mode loopback} \
  --clearsign -o "${RELEASE_DIR}/InRelease" "${RELEASE_DIR}/Release"

echo "Generating index.html..."
PKG_COUNT=$(grep -c '^Package:' "${DISTS_DIR}/Packages" || echo 0)
PKG_LIST=""
while IFS= read -r pkg; do
  name=$(echo "$pkg" | cut -d'|' -f1)
  ver=$(echo "$pkg" | cut -d'|' -f2)
  file=$(echo "$pkg" | cut -d'|' -f3)
  PKG_LIST="${PKG_LIST}<tr><td><a href=\"${file}\">${name}</a></td><td>${ver}</td></tr>"
done < <(awk '/^Package:/{p=$2} /^Version:/{v=$2} /^Filename:/{f=$2; print p"|"v"|"f}' "${DISTS_DIR}/Packages")

cat > "${OUTPUT_DIR}/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Linagora LemonLDAP::NG Plugins — Debian Repository</title>
  <style>body{font-family:sans-serif;max-width:700px;margin:2em auto;padding:0 1em}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px 10px;text-align:left}th{background:#f5f5f5}pre{background:#f4f4f4;padding:1em;overflow-x:auto}code{font-size:.9em}</style>
</head>
<body>
  <h1>Debian Repository</h1>
  <p>This APT repository contains <strong>${PKG_COUNT}</strong> package(s) for
  <a href="https://lemonldap-ng.org">LemonLDAP::NG</a>.</p>
  <h2>Setup</h2>
  <pre>curl -fsSL ../store-key.asc \\
  | sudo gpg --dearmor -o /usr/share/keyrings/linagora-llng-plugins.gpg

echo "deb [signed-by=/usr/share/keyrings/linagora-llng-plugins.gpg] \\
  \$(dirname \$(curl -sI . | grep -i location | awk '{print \$2}' | tr -d '\\r'))/debian stable main" \\
  | sudo tee /etc/apt/sources.list.d/linagora-llng-plugins.list

sudo apt update</pre>
  <h2>Packages</h2>
  <table>
    <thead><tr><th>Package</th><th>Version</th></tr></thead>
    <tbody>${PKG_LIST}</tbody>
  </table>
  <p><small><a href="../">Back to store</a></small></p>
</body>
</html>
EOF

echo "APT repository built at ${OUTPUT_DIR}/"
echo ""
echo "Structure:"
find "$OUTPUT_DIR" -type f | sort
