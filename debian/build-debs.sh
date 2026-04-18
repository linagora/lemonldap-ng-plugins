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
Conflicts: liblemonldap-ng-common-perl (>= 2.24.0~), liblemonldap-ng-portal-perl (>= 2.23.0~)
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
register_autoloader() {
    # On LLNG < 2.24.0 the Autoloader plugin is not part of the default
    # @pList — register it once in customPlugins so store plugins that
    # ship an autoload rule actually load without manual intervention.
    cli=$(command -v lemonldap-ng-cli 2>/dev/null || true)
    [ -n "$cli" ] || return 0
    current=$("$cli" --json 1 get customPlugins 2>/dev/null || true)
    case "$current" in
        *Plugins::Autoloader*) return 0 ;;
    esac
    value=$(echo "$current" | sed -e 's/^"//' -e 's/"$//' -e 's/^null$//')
    if [ -n "$value" ]; then
        new="$value, ::Plugins::Autoloader"
    else
        new="::Plugins::Autoloader"
    fi
    "$cli" --yes 1 set customPlugins "$new" >/dev/null 2>&1 || true
}
case "$1" in
  configure)
    register_autoloader
    ;;
  triggered)
    if [ -x /usr/share/lemonldap-ng/bin/lemonldap-ng-store ]; then
      /usr/share/lemonldap-ng/bin/lemonldap-ng-store rebuild || true
    fi
    ;;
  abort-upgrade|abort-remove|abort-deconfigure)
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

# Install OIDCPlugin.pm backport (needed by OIDC plugins on LLNG < 2.23.0)
install_file "${REPO_ROOT}/store/lib/Lemonldap/NG/Portal/Lib/OIDCPlugin.pm" \
  "${STORE_BUILD}/usr/share/perl5/Lemonldap/NG/Portal/Lib/OIDCPlugin.pm"

# Install Autoloader plugin backport (needed on LLNG < 2.24.0 to auto-load
# store plugins from /etc/lemonldap-ng/autoload.d/; on LLNG >= 2.24.0 the
# upstream Autoloader takes precedence)
install_file "${REPO_ROOT}/store/lib/Lemonldap/NG/Portal/Plugins/Autoloader.pm" \
  "${STORE_BUILD}/usr/share/perl5/Lemonldap/NG/Portal/Plugins/Autoloader.pm"

# Ship an empty autoload directory so plugins installed afterwards can drop
# JSON rule files into it without having to create the dir themselves
install -d -m 0755 "${STORE_BUILD}/etc/lemonldap-ng/autoload.d"

dpkg-deb --root-owner-group --build "${STORE_BUILD}" \
  "${OUTPUT_DIR}/linagora-lemonldap-ng-store_${COMMON_VERSION}_all.deb"
echo "  -> linagora-lemonldap-ng-store_${COMMON_VERSION}_all.deb"

##############################################################################
# Build linagora-llng-build-manager-files
##############################################################################
echo "Building linagora-llng-build-manager-files ${COMMON_VERSION}..."

BMF_BUILD="${WORKDIR}/build-manager-files"
install_dir "${BMF_BUILD}/DEBIAN"

cat > "${BMF_BUILD}/DEBIAN/control" <<EOF
Package: linagora-llng-build-manager-files
Version: ${COMMON_VERSION}
Architecture: all
Maintainer: Linagora <https://linagora.com>
Depends: liblemonldap-ng-manager-perl (>= 2.22~)
Conflicts: liblemonldap-ng-manager-perl (>= 2.23.0~)
Section: web
Priority: optional
Description: llng-build-manager-files with plugin overrides support (backport)
 Provides llng-build-manager-files with --plugins-dir support for
 LemonLDAP::NG Manager versions prior to 2.23.0. Install this package
 if you use plugins with manager-overrides on LLNG < 2.23.0.
EOF

install -D -m 0755 "${REPO_ROOT}/store/scripts/llng-build-manager-files" \
  "${BMF_BUILD}/usr/share/lemonldap-ng/bin/llng-build-manager-files"

dpkg-deb --root-owner-group --build "${BMF_BUILD}" \
  "${OUTPUT_DIR}/linagora-llng-build-manager-files_${COMMON_VERSION}_all.deb"
echo "  -> linagora-llng-build-manager-files_${COMMON_VERSION}_all.deb"

##############################################################################
# Build linagora-llng-crowdsec-filters
##############################################################################
echo "Building linagora-llng-crowdsec-filters ${COMMON_VERSION}..."

CSF_BUILD="${WORKDIR}/crowdsec-filters"
CSF_SRC="${REPO_ROOT}/crowdsec-filters"
install_dir "${CSF_BUILD}/DEBIAN"

cat > "${CSF_BUILD}/DEBIAN/control" <<EOF
Package: linagora-llng-crowdsec-filters
Version: ${COMMON_VERSION}
Architecture: all
Maintainer: Linagora <https://linagora.com>
Recommends: liblemonldap-ng-portal-perl (>= 2.23.0~)
Section: web
Priority: optional
Description: CrowdSec-compatible HTTP filters for LemonLDAP::NG (>= 2.23.0)
 Pattern files consumed by the LemonLDAP::NG built-in CrowdSec agent to
 detect and report suspicious HTTP requests (admin probing, backdoors,
 trending CVE URIs, path traversal, WordPress scans, etc.). Installs under
 /var/lib/lemonldap-ng/crowdsec-filters/. Point the portal's
 crowdsecFilters parameter to that directory and set crowdsecAgent /
 crowdsecMachineId / crowdsecPassword to push alerts to your LAPI.
EOF

# Install filters preserving dotfiles (.scenario, .maxfailures, .timewindow)
CSF_DEST="${CSF_BUILD}/var/lib/lemonldap-ng/crowdsec-filters"
install_dir "${CSF_DEST}"
( cd "${CSF_SRC}" && find . -mindepth 1 -type d ! -name '.' \
    -exec install -d -m 0755 "${CSF_DEST}/{}" \; )
( cd "${CSF_SRC}" && find . -type f ! -name 'README.md' | while IFS= read -r f; do
    install -D -m 0644 "${CSF_SRC}/${f#./}" "${CSF_DEST}/${f#./}"
  done )

# Ship README and copyright under /usr/share/doc/<pkg>/
install_file "${CSF_SRC}/README.md" \
  "${CSF_BUILD}/usr/share/doc/linagora-llng-crowdsec-filters/README"

cat > "${CSF_BUILD}/usr/share/doc/linagora-llng-crowdsec-filters/copyright" <<'COPYRIGHT'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: linagora-llng-crowdsec-filters
Source: https://github.com/linagora/lemonldap-ng-plugins
Comment: partially imported from crowdsec.net, copyright CrowdSecurity.
 Pattern data (URI lists, backdoor filenames, probe strings) originates from
 https://hub-data.crowdsec.net/ and https://github.com/crowdsecurity/hub,
 both MIT-licensed. Regex transformations and LemonLDAP::NG scenario
 metadata (.scenario, .maxfailures, .timewindow) are authored by Linagora.

Files: *
Copyright: 2025 CrowdSecurity
           2025 Linagora <https://linagora.com>
License: Expat

License: Expat
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 .
 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.
 .
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
COPYRIGHT

dpkg-deb --root-owner-group --build "${CSF_BUILD}" \
  "${OUTPUT_DIR}/linagora-llng-crowdsec-filters_${COMMON_VERSION}_all.deb"
echo "  -> linagora-llng-crowdsec-filters_${COMMON_VERSION}_all.deb"

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
    if [ -n "$depends" ]; then
      depends="${depends}, linagora-lemonldap-ng-plugin-${dep}"
    else
      depends="linagora-lemonldap-ng-plugin-${dep}"
    fi
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

  # Generate autoload rule(s) from plugin.json.autoload.
  # Each entry maps to /etc/lemonldap-ng/autoload.d/NN-slug[-i].json so the
  # Autoloader plugin (shipped by linagora-lemonldap-ng-store and/or part
  # of the default @pList on LLNG >= 2.24.0) picks them up at portal init.
  autoload_json=$(jq -c '.autoload // null' "$plugin_json")
  if [ "$autoload_json" != "null" ]; then
    autoload_dest="${PKG_BUILD}/etc/lemonldap-ng/autoload.d"
    install_dir "$autoload_dest"
    slug=$(echo "$name" | tr 'A-Z' 'a-z' | tr -cs 'a-z0-9' '-' \
        | sed -e 's/^-//' -e 's/-$//')
    [ -n "$slug" ] || slug="$name"
    custom_plugins_for_autoload=$(jq -r '.customPlugins // ""' "$plugin_json")

    _write_autoload_entry() {
        local entry="$1" out_file="$2"
        echo "$entry" | jq --arg cp "$custom_plugins_for_autoload" '
            del(.priority)
            | if .module == null or .module == "" then .module = $cp else . end
        ' > "$out_file"
    }

    case "$(echo "$autoload_json" | jq -r 'type')" in
      array)
        count=$(echo "$autoload_json" | jq 'length')
        i=0
        while [ "$i" -lt "$count" ]; do
          entry=$(echo "$autoload_json" | jq -c ".[$i]")
          prio=$(echo "$entry" | jq -r '.priority // 50')
          prio_padded=$(printf '%02d' "$prio" 2>/dev/null || echo "$prio")
          _write_autoload_entry "$entry" \
            "${autoload_dest}/${prio_padded}-${slug}-${i}.json"
          i=$((i + 1))
        done
        ;;
      object)
        prio=$(echo "$autoload_json" | jq -r '.priority // 50')
        prio_padded=$(printf '%02d' "$prio" 2>/dev/null || echo "$prio")
        _write_autoload_entry "$autoload_json" \
          "${autoload_dest}/${prio_padded}-${slug}.json"
        ;;
      *)
        echo "  Warning: plugin.json .autoload must be object or array, skipping"
        ;;
    esac
  fi

  # Install portal-templates/ -> /usr/share/lemonldap-ng/portal/templates/
  if [ -d "${plugin_dir}/portal-templates" ]; then
    while IFS= read -r tpl_file; do
      rel="${tpl_file#${plugin_dir}/portal-templates/}"
      install_file "$tpl_file" "${PKG_BUILD}/usr/share/lemonldap-ng/portal/templates/${rel}"
    done < <(find "${plugin_dir}/portal-templates" -type f)
  fi

  # Install portal-static/ -> /usr/share/lemonldap-ng/portal/htdocs/static/
  if [ -d "${plugin_dir}/portal-static" ]; then
    while IFS= read -r static_file; do
      rel="${static_file#${plugin_dir}/portal-static/}"
      install_file "$static_file" "${PKG_BUILD}/usr/share/lemonldap-ng/portal/htdocs/static/${rel}"
    done < <(find "${plugin_dir}/portal-static" -type f)
  fi

  # Install portal-translations/*.json: merge into portal language files
  if [ -d "${plugin_dir}/portal-translations" ]; then
    while IFS= read -r tr_file; do
      lang_name="$(basename "$tr_file")"
      dst="/usr/share/lemonldap-ng/portal/htdocs/static/languages/${lang_name}"
      dst_build="${PKG_BUILD}${dst}"
      # postinst will merge these at install time
      install_file "$tr_file" "${PKG_BUILD}/usr/share/lemonldap-ng/portal/plugin-translations/${name}/${lang_name}"
    done < <(find "${plugin_dir}/portal-translations" -name "*.json")

    # Add postinst to merge translations
    cat > "${PKG_BUILD}/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
LANG_DIR="/usr/share/lemonldap-ng/portal/htdocs/static/languages"
PLUGIN_TR_DIR="/usr/share/lemonldap-ng/portal/plugin-translations"

merge_translations() {
  for plugin_dir in "$PLUGIN_TR_DIR"/*/; do
    [ -d "$plugin_dir" ] || continue
    for tr_file in "$plugin_dir"*.json; do
      [ -f "$tr_file" ] || continue
      lang="$(basename "$tr_file")"
      target="${LANG_DIR}/${lang}"
      [ -f "$target" ] || continue
      # Merge: add keys from plugin that don't exist in target
      perl -MJSON -e '
        open my $tf, "<", $ARGV[0] or die $!;
        local $/; my $base = decode_json(<$tf>); close $tf;
        open my $sf, "<", $ARGV[1] or die $!;
        my $ext = decode_json(<$sf>); close $sf;
        for (keys %$ext) { $base->{$_} //= $ext->{$_} }
        open my $of, ">", $ARGV[0] or die $!;
        print $of JSON->new->utf8->pretty->canonical->encode($base);
        close $of;
      ' "$target" "$tr_file" 2>/dev/null || true
    done
  done
}

case "$1" in
  configure)
    merge_translations
    ;;
esac
exit 0
POSTINST
    chmod 0755 "${PKG_BUILD}/DEBIAN/postinst"
  fi

  dpkg-deb --root-owner-group --build "${PKG_BUILD}" "${OUTPUT_DIR}/${pkg_name}_${version}_all.deb"
  echo "  -> ${pkg_name}_${version}_all.deb"
done

echo "Done. Packages written to ${OUTPUT_DIR}/"
ls -lh "${OUTPUT_DIR}/"*.deb
