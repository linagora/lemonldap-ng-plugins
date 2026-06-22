#!/bin/bash
# Build the RPM counterpart of debian/build-debs.sh.
#
# Scope (for now): linagora-lemonldap-ng-store only — the store CLI, its Perl
# modules and the Autoloader backport, for RPM-based distributions (EL9/EL10
# i.e. RHEL/Rocky/AlmaLinux 9 & 10). Everything shipped is pure Perl + shell,
# so a single noarch package serves both EL9 and EL10.
#
# Mirrors the store target of debian/build-debs.sh:
#   - /usr/share/perl5/vendor_perl/Lemonldap/NG/Common/Store*.pm
#   - /usr/share/perl5/vendor_perl/Lemonldap/NG/Portal/Plugins/Autoloader.pm
#   - /usr/bin/lemonldap-ng-store
#   - /etc/lemonldap-ng/autoload.d (empty, for plugins to drop rules into)
#   - %post  : register the Autoloader in customPlugins (LLNG < 2.24.0)
#   - file trigger on manager-overrides.d : rebuild the store (== dpkg trigger)
#
# Requirements: rpmbuild (rpm-build). createrepo_c + gpg are only needed by
# rpm/build-repo.sh. perl_vendorlib is forced to the EL layout so the build is
# reproducible even when run on a non-RPM host (e.g. the Ubuntu CI runner).
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

# EL Perl vendor library (arch-independent, identical on EL9 and EL10).
# Forced explicitly so the resulting noarch RPM always lands in the right place,
# regardless of the build host's own perl.
PERL_VENDORLIB="/usr/share/perl5/vendor_perl"

TOPDIR="$(mktemp -d)"
trap 'rm -rf "$TOPDIR"' EXIT
mkdir -p "$TOPDIR"/{BUILD,BUILDROOT,RPMS,SPECS,SOURCES,SRPMS}

##############################################################################
# linagora-lemonldap-ng-store
##############################################################################
echo "Building linagora-lemonldap-ng-store ${COMMON_VERSION}..."

SPEC="${TOPDIR}/SPECS/linagora-lemonldap-ng-store.spec"

cat > "$SPEC" <<'SPECEOF'
# Pure-perl/noarch backport package: no debuginfo, no byte-compilation.
%global debug_package %{nil}
%define _build_id_links none
# Forced by the build script (see --define) so this is reproducible off-EL.
%{!?perl_vendorlib: %global perl_vendorlib /usr/share/perl5/vendor_perl}

Name:           linagora-lemonldap-ng-store
Version:        %{store_version}
Release:        1%{?dist}
Summary:        Plugin store manager for LemonLDAP::NG (backport)
License:        GPL-2.0-or-later
URL:            https://github.com/linagora/lemonldap-ng-plugins
BuildArch:      noarch

# Backport scope: LLNG core ships lemonldap-ng-store itself from 2.24.0, so
# this package targets the 2.23.x window only (mirrors the Debian bounds).
Requires:       lemonldap-ng-common >= 2.23.0
Conflicts:      lemonldap-ng-common >= 2.24.0
Requires:       perl(JSON)
Requires:       perl(Config::IniFiles)
Requires:       perl(LWP::UserAgent)

%description
Provides lemonldap-ng-store for LemonLDAP::NG versions prior to 2.24.0,
together with the Autoloader plugin backport so store-installed plugins
load without manual @pList edits. Backport of the Debian
linagora-lemonldap-ng-store package for RHEL/Rocky/AlmaLinux 9 & 10.

%prep
# Built straight from the repository tree (passed via %%{repo_root}); nothing
# to unpack.

%build
# Pure Perl + shell: nothing to compile.

%install
rm -rf %{buildroot}

# Perl modules -> vendor_perl (same tree LLNG core uses for Common/)
install -D -m 0644 %{repo_root}/store/lib/Lemonldap/NG/Common/Store.pm \
  %{buildroot}%{perl_vendorlib}/Lemonldap/NG/Common/Store.pm
install -d -m 0755 %{buildroot}%{perl_vendorlib}/Lemonldap/NG/Common/Store
for pm in %{repo_root}/store/lib/Lemonldap/NG/Common/Store/*.pm; do
  install -D -m 0644 "$pm" \
    "%{buildroot}%{perl_vendorlib}/Lemonldap/NG/Common/Store/$(basename "$pm")"
done

# Autoloader plugin backport. On LLNG < 2.24.0 it is not part of @pList; %%post
# registers it in customPlugins. On LLNG >= 2.24.0 the upstream one wins (and
# this package conflicts with common >= 2.24.0 anyway).
install -D -m 0644 %{repo_root}/store/lib/Lemonldap/NG/Portal/Plugins/Autoloader.pm \
  %{buildroot}%{perl_vendorlib}/Lemonldap/NG/Portal/Plugins/Autoloader.pm

# CLI. Unlike Debian (which hides it under /usr/share/.../bin), install into
# /usr/bin so `lemonldap-ng-store` is on PATH as the docs assume; Verify.pm
# scans /usr/bin too.
install -D -m 0755 %{repo_root}/store/bin/lemonldap-ng-store \
  %{buildroot}%{_bindir}/lemonldap-ng-store

# Ship an empty autoload directory so plugins installed afterwards can drop
# JSON rule files into it without creating the dir themselves.
install -d -m 0755 %{buildroot}%{_sysconfdir}/lemonldap-ng/autoload.d

%files
%{_bindir}/lemonldap-ng-store
%{perl_vendorlib}/Lemonldap/NG/Common/Store.pm
%dir %{perl_vendorlib}/Lemonldap/NG/Common/Store
%{perl_vendorlib}/Lemonldap/NG/Common/Store/*.pm
# Co-owned with lemonldap-ng-portal when it is installed (RPM allows shared
# directory ownership); owned outright on manager-only hosts where portal is
# absent.
%dir %{perl_vendorlib}/Lemonldap/NG/Portal
%dir %{perl_vendorlib}/Lemonldap/NG/Portal/Plugins
%{perl_vendorlib}/Lemonldap/NG/Portal/Plugins/Autoloader.pm
# /etc/lemonldap-ng itself is owned by lemonldap-ng-common (Required).
%dir %{_sysconfdir}/lemonldap-ng/autoload.d

%post
# On LLNG < 2.24.0 the Autoloader plugin is not part of the default @pList —
# register it once in customPlugins so store plugins that ship an autoload
# rule actually load without manual intervention.
if [ "$1" -ge 1 ]; then
  cli=$(command -v lemonldap-ng-cli 2>/dev/null || true)
  if [ -n "$cli" ]; then
    current=$("$cli" --json 1 get customPlugins 2>/dev/null || true)
    case "$current" in
      *Plugins::Autoloader*) : ;;
      *)
        value=$(echo "$current" | sed -e 's/^"//' -e 's/"$//' -e 's/^null$//')
        if [ -n "$value" ]; then
          new="$value, ::Plugins::Autoloader"
        else
          new="::Plugins::Autoloader"
        fi
        "$cli" --yes 1 set customPlugins "$new" >/dev/null 2>&1 || true
        ;;
    esac
  fi
fi

# RPM file trigger == the dpkg "interest-noawait" triggers: whenever any
# package drops or removes a manager override, rebuild the store cache.
%transfiletriggerin -- %{_sysconfdir}/lemonldap-ng/manager-overrides.d %{_datadir}/lemonldap-ng/manager-overrides.d
if [ -x %{_bindir}/lemonldap-ng-store ]; then
  %{_bindir}/lemonldap-ng-store rebuild || true
fi

%transfiletriggerpostun -- %{_sysconfdir}/lemonldap-ng/manager-overrides.d %{_datadir}/lemonldap-ng/manager-overrides.d
if [ -x %{_bindir}/lemonldap-ng-store ]; then
  %{_bindir}/lemonldap-ng-store rebuild || true
fi

%changelog
* Thu Jun 18 2026 Linagora <https://linagora.com> - %{store_version}-1
- RPM backport of linagora-lemonldap-ng-store for EL9/EL10
SPECEOF

rpmbuild -bb "$SPEC" \
  --define "_topdir ${TOPDIR}" \
  --define "repo_root ${REPO_ROOT}" \
  --define "store_version ${COMMON_VERSION}" \
  --define "perl_vendorlib ${PERL_VENDORLIB}" \
  --define "dist %{nil}"

find "${TOPDIR}/RPMS" -name '*.rpm' -exec cp -v {} "${OUTPUT_DIR}/" \;

echo "Done. RPMs written to ${OUTPUT_DIR}/"
ls -lh "${OUTPUT_DIR}/"*.rpm
