#!/bin/bash
set -e

OUTPUT_DIR="${1:?Usage: $0 <output-dir>}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

# Version from env var TAG (e.g. "v0.1.1" -> "0.1.1", or "0.1.1" as-is)
if [ -z "$TAG" ]; then
  echo "ERROR: TAG environment variable is required (e.g. TAG=0.1.1 or TAG=v0.1.1)" >&2
  exit 1
fi
COMMON_VERSION="${TAG#v}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# Perl modules whose Debian package name doesn't follow the lib<name>-perl convention
declare -A PERL_DEB_MAP=(
  ["Date::Parse"]="libtimedate-perl"
  ["Date::Format"]="libtimedate-perl"
  ["URI::Escape"]="liburi-perl"
  ["URI"]="liburi-perl"
)

# Convert a Perl module name to a Debian package name
# e.g. Net::DNS -> libnet-dns-perl
perl_mod_to_deb() {
  local mod="$1"
  if [ -n "${PERL_DEB_MAP[$mod]+x}" ]; then
    echo "${PERL_DEB_MAP[$mod]}"
    return
  fi
  echo "$mod" | tr '[:upper:]' '[:lower:]' | sed 's/::/-/g' | sed 's/^/lib/' | sed 's/$/-perl/'
}

# Build the control file Depends field from perl_requires JSON object
# perl_requires: {"Module::Name": "version", ...}
# Returns comma-separated Debian depends
build_perl_depends() {
  local perl_requires_json="$1"
  local base_dep="$2"
  local deps="$base_dep"

  # Iterate over keys
  while IFS= read -r entry; do
    local mod version deb_pkg
    mod="$(echo "$entry" | jq -r '.[0]')"
    version="$(echo "$entry" | jq -r '.[1]')"
    deb_pkg="$(perl_mod_to_deb "$mod")"
    if [ "$version" = "0" ] || [ -z "$version" ]; then
      deps="${deps}, ${deb_pkg}"
    else
      deps="${deps}, ${deb_pkg} (>= ${version})"
    fi
  done < <(echo "$perl_requires_json" | jq -c 'to_entries[] | [.key, .value]')

  echo "$deps"
}

# Install a directory into the deb build tree with correct permissions
install_dir() {
  local dir="$1"
  install -d -m 0755 "$dir"
}

# Install a file into the deb build tree with correct permissions
install_file() {
  local src="$1"
  local dst="$2"
  install -D -m 0644 "$src" "$dst"
}

# Install a script with executable permissions
install_script() {
  local src="$1"
  local dst="$2"
  install -D -m 0755 "$src" "$dst"
}

##############################################################################
# Build linagora-lemonldap-ng-store
##############################################################################
echo "Building linagora-lemonldap-ng-store ${COMMON_VERSION}..."

STORE_BUILD="${WORKDIR}/store"
install_dir "${STORE_BUILD}/DEBIAN"

cat > "${STORE_BUILD}/DEBIAN/control" <<EOF
Package: linagora-lemonldap-ng-store
Version: ${COMMON_VERSION}
Architecture: all
Maintainer: Linagora <https://linagora.com>
Depends: liblemonldap-ng-common-perl (<< 2.24.0~), libjson-perl, libconfig-inifiles-perl, libwww-perl
Conflicts: liblemonldap-ng-common-perl (>= 2.24.0~)
Section: web
Priority: optional
Description: Plugin store manager for LemonLDAP::NG (backport)
 Provides lemonldap-ng-store for LemonLDAP::NG versions prior to 2.24.0.
EOF

# triggers file
cat > "${STORE_BUILD}/DEBIAN/triggers" <<'EOF'
interest-noawait /etc/lemonldap-ng/manager-overrides.d
interest-noawait /usr/share/lemonldap-ng/manager-overrides.d
interest-noawait /usr/local/etc/lemonldap-ng/manager-overrides.d
EOF

# postinst
cat > "${STORE_BUILD}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
case "$1" in
  triggered)
    if [ -x /usr/share/lemonldap-ng/bin/lemonldap-ng-store ]; then
      /usr/share/lemonldap-ng/bin/lemonldap-ng-store rebuild || true
    fi
    ;;
  configure|abort-upgrade|abort-remove|abort-deconfigure)
    ;;
esac
#DEBHELPER#
exit 0
EOF
chmod 0755 "${STORE_BUILD}/DEBIAN/postinst"

# Install bin
install -D -m 0755 "${REPO_ROOT}/store/bin/lemonldap-ng-store" \
  "${STORE_BUILD}/usr/share/lemonldap-ng/bin/lemonldap-ng-store"

# Install Perl modules
for pm_file in "${REPO_ROOT}/store/lib/Lemonldap/NG/Common/Store.pm" \
               "${REPO_ROOT}"/store/lib/Lemonldap/NG/Common/Store/*.pm; do
  rel="${pm_file#${REPO_ROOT}/store/lib/}"
  install_file "$pm_file" "${STORE_BUILD}/usr/share/perl5/${rel}"
done

dpkg-deb --root-owner-group --build "${STORE_BUILD}" \
  "${OUTPUT_DIR}/linagora-lemonldap-ng-store_${COMMON_VERSION}_all.deb"
echo "  -> linagora-lemonldap-ng-store_${COMMON_VERSION}_all.deb"

##############################################################################
# Build individual plugin packages
##############################################################################
for plugin_json in "${REPO_ROOT}/plugins/"*/plugin.json; do
  plugin_dir="$(dirname "$plugin_json")"
  plugin_basename="$(basename "$plugin_dir")"

  name="$(jq -r '.name' "$plugin_json")"
  version="$(jq -r '.version' "$plugin_json")"
  summary="$(jq -r '.summary // "LemonLDAP::NG plugin"' "$plugin_json")"
  author="$(jq -r '.author // ""' "$plugin_json")"
  perl_requires="$(jq -c '.perl_requires // {}' "$plugin_json")"

  pkg_name="linagora-lemonldap-ng-plugin-${name}"
  maintainer="${author:-Linagora <https://linagora.com>}"

  echo "Building ${pkg_name} ${version}..."

  PKG_BUILD="${WORKDIR}/${plugin_basename}"
  rm -rf "$PKG_BUILD"
  install_dir "${PKG_BUILD}/DEBIAN"

  # Build Depends
  # Pre-Depends ensures the store (and its triggers) is fully configured
  # before the plugin installs files into the overrides directory
  pre_depends="liblemonldap-ng-common-perl (>= 2.24.0) | linagora-lemonldap-ng-store"
  depends="$(build_perl_depends "$perl_requires" "")"
  # Remove leading ", " from depends if base was empty
  depends="${depends#, }"

  # Add inter-plugin dependencies
  while IFS= read -r dep; do
    [ -z "$dep" ] && continue
    depends="${depends}, linagora-lemonldap-ng-plugin-${dep}"
  done < <(jq -r '.depends // [] | .[]' "$plugin_json")

  # control file
  {
    echo "Package: ${pkg_name}"
    echo "Version: ${version}"
    echo "Architecture: all"
    echo "Maintainer: ${maintainer}"
    echo "Pre-Depends: ${pre_depends}"
    [ -n "$depends" ] && echo "Depends: ${depends}"
    echo "Section: web"
    echo "Priority: optional"
    echo "Description: ${summary}"
  } > "${PKG_BUILD}/DEBIAN/control"

  # Install Perl modules: lib/Lemonldap/NG/**/*.pm -> /usr/share/perl5/Lemonldap/NG/**/*.pm
  if [ -d "${plugin_dir}/lib" ]; then
    while IFS= read -r pm_file; do
      # relative path under plugin_dir/lib
      rel="${pm_file#${plugin_dir}/lib/}"
      dst="${PKG_BUILD}/usr/share/perl5/${rel}"
      install_file "$pm_file" "$dst"
    done < <(find "${plugin_dir}/lib" -name "*.pm")
  fi

  # Install manager-overrides/*.json -> /etc/lemonldap-ng/manager-overrides.d/
  if [ -d "${plugin_dir}/manager-overrides" ]; then
    install_dir "${PKG_BUILD}/etc/lemonldap-ng/manager-overrides.d"
    while IFS= read -r json_file; do
      dst="${PKG_BUILD}/etc/lemonldap-ng/manager-overrides.d/$(basename "$json_file")"
      install_file "$json_file" "$dst"
    done < <(find "${plugin_dir}/manager-overrides" -maxdepth 1 -name "*.json")
  fi

  dpkg-deb --root-owner-group --build "${PKG_BUILD}" "${OUTPUT_DIR}/${pkg_name}_${version}_all.deb"
  echo "  -> ${pkg_name}_${version}_all.deb"
done

echo "Done. Packages written to ${OUTPUT_DIR}/"
ls -lh "${OUTPUT_DIR}/"*.deb
