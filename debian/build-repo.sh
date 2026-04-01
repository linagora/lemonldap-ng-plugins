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

echo "APT repository built at ${OUTPUT_DIR}/"
echo ""
echo "Structure:"
find "$OUTPUT_DIR" -type f | sort
