#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
	echo "Usage: $0 /path/to/pfSense-pkg-WireGuard-ClientExport.pkg" >&2
	exit 64
fi

WGCE_PACKAGE=$1
WGCE_SOURCE_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

if [ ! -f "${WGCE_PACKAGE}" ]; then
	echo "Package not found: ${WGCE_PACKAGE}" >&2
	exit 66
fi

WGCE_AUDIT_DIR=$(mktemp -d -t wgclientexport-audit.XXXXXX)

cleanup_wgce_audit() {
	if [ -n "${WGCE_AUDIT_DIR}" ] && [ -d "${WGCE_AUDIT_DIR}" ]; then
		rm -rf -- "${WGCE_AUDIT_DIR}"
	fi
}

trap cleanup_wgce_audit EXIT HUP INT TERM

tar -tf "${WGCE_PACKAGE}" | while IFS= read -r WGCE_ENTRY; do
	WGCE_ENTRY=${WGCE_ENTRY#/}
	case "${WGCE_ENTRY}" in
		+MANIFEST|+COMPACT_MANIFEST|+POST_INSTALL|+DEINSTALL|+POST_DEINSTALL) ;;
		etc/inc|etc/inc/|etc/inc/priv|etc/inc/priv/) ;;
		etc/inc/priv/wgclientexport.priv.inc) ;;
		usr/local/pkg/wgclientexport.xml) ;;
		usr/local/pkg/wgclientexport|usr/local/pkg/wgclientexport/) ;;
		usr/local/pkg/wgclientexport/*.inc) ;;
		usr/local/www/wgclientexport|usr/local/www/wgclientexport/) ;;
		usr/local/www/wgclientexport/vpn_wg_client_export.php) ;;
		usr/local/www/wgclientexport/js|usr/local/www/wgclientexport/js/) ;;
		usr/local/www/wgclientexport/js/qrcode.js) ;;
		usr/local/share/pfSense-pkg-WireGuard-ClientExport|usr/local/share/pfSense-pkg-WireGuard-ClientExport/) ;;
		usr/local/share/pfSense-pkg-WireGuard-ClientExport/info.xml) ;;
		usr/local/share/pfSense-pkg-WireGuard-ClientExport/LICENSE) ;;
		usr/local/share/pfSense-pkg-WireGuard-ClientExport/THIRD_PARTY_NOTICES.md) ;;
		*)
			echo "Unexpected package path: ${WGCE_ENTRY}" >&2
			exit 1
			;;
	esac
done

tar -xf "${WGCE_PACKAGE}" -C "${WGCE_AUDIT_DIR}"

test -f "${WGCE_AUDIT_DIR}/+MANIFEST"
WGCE_LICENSE="${WGCE_AUDIT_DIR}/usr/local/share/pfSense-pkg-WireGuard-ClientExport/LICENSE"
test -s "${WGCE_LICENSE}"
grep -q 'Apache License' "${WGCE_LICENSE}"
cmp -s "${WGCE_SOURCE_ROOT}/LICENSE" "${WGCE_LICENSE}"
grep -q 'pfSense-pkg-WireGuard-ClientExport' \
	"${WGCE_AUDIT_DIR}/+MANIFEST"
grep -q 'APACHE20' "${WGCE_AUDIT_DIR}/+MANIFEST"
grep -q 'pfSense-pkg-WireGuard' "${WGCE_AUDIT_DIR}/+MANIFEST"
grep -Eq '"maintainer"[[:space:]]*:[[:space:]]*"sirius0@users\.noreply\.github\.com"' \
	"${WGCE_AUDIT_DIR}/+MANIFEST"
grep -Eq '"www"[[:space:]]*:[[:space:]]*"https://github\.com/sirius0/pfsense-pkg-wireguard-client-export"' \
	"${WGCE_AUDIT_DIR}/+MANIFEST"
grep -Eq '"abi"[[:space:]]*:[[:space:]]*"FreeBSD:16:amd64"' \
	"${WGCE_AUDIT_DIR}/+MANIFEST"
grep -Eq '"arch"[[:space:]]*:[[:space:]]*"freebsd:16:x86:64"' \
	"${WGCE_AUDIT_DIR}/+MANIFEST"
grep -Eq '"version"[[:space:]]*:[[:space:]]*"0\.2\.13_4"' \
	"${WGCE_AUDIT_DIR}/+MANIFEST"

WGCE_BOOTSTRAP="${WGCE_AUDIT_DIR}/usr/local/pkg/wgclientexport/bootstrap.inc"
WGCE_PACKAGE_XML="${WGCE_AUDIT_DIR}/usr/local/pkg/wgclientexport.xml"
WGCE_INFO_XML="${WGCE_AUDIT_DIR}/usr/local/share/pfSense-pkg-WireGuard-ClientExport/info.xml"
WGCE_MANIFEST_VERSION=$(awk '
	match($0, /"version"[[:space:]]*:[[:space:]]*"[^"]+"/) {
		value = substr($0, RSTART, RLENGTH)
		sub(/^[^:]*:[[:space:]]*"/, "", value)
		sub(/"$/, "", value)
		print value
		exit
	}
' "${WGCE_AUDIT_DIR}/+MANIFEST")
WGCE_RUNTIME_VERSION=$(sed -n \
	"s/^[[:space:]]*define('WGCLIENTEXPORT_VERSION',[[:space:]]*'\([^']*\)');[[:space:]]*$/\1/p" \
	"${WGCE_BOOTSTRAP}")
WGCE_PACKAGE_XML_VERSION=$(sed -n \
	's|^[[:space:]]*<version>\([^<]*\)</version>[[:space:]]*$|\1|p' \
	"${WGCE_PACKAGE_XML}")
WGCE_INFO_XML_VERSION=$(sed -n \
	's|^[[:space:]]*<version>\([^<]*\)</version>[[:space:]]*$|\1|p' \
	"${WGCE_INFO_XML}")

if [ -z "${WGCE_MANIFEST_VERSION}" ] || [ -z "${WGCE_RUNTIME_VERSION}" ] \
    || [ -z "${WGCE_PACKAGE_XML_VERSION}" ] || [ -z "${WGCE_INFO_XML_VERSION}" ]; then
	echo 'Unable to determine every packaged version.' >&2
	exit 1
fi
for WGCE_EMBEDDED_VERSION in \
	"${WGCE_RUNTIME_VERSION}" "${WGCE_PACKAGE_XML_VERSION}" "${WGCE_INFO_XML_VERSION}"
do
	if [ "${WGCE_EMBEDDED_VERSION}" != "${WGCE_MANIFEST_VERSION}" ]; then
		echo "Embedded version ${WGCE_EMBEDDED_VERSION} does not match manifest version ${WGCE_MANIFEST_VERSION}." >&2
		exit 1
	fi
done

if find "${WGCE_AUDIT_DIR}" -type f \
	! -name '+MANIFEST' ! -name '+COMPACT_MANIFEST' \
	-exec grep -E -n '[A-Za-z0-9+/]{43}=' {} +; then
	echo 'Possible embedded WireGuard key material found in package contents.' >&2
	exit 1
fi

if grep -R -E -n \
	'install_cron_job|/etc/rc\.d|send_smtp_message|wgx_|telemetry|config_set_path\(.?(filter|nat|interfaces)' \
	"${WGCE_AUDIT_DIR}/usr/local/pkg" \
	"${WGCE_AUDIT_DIR}/usr/local/www" 2>/dev/null; then
	echo 'Forbidden v1 service or firewall mutation capability found.' >&2
	exit 1
fi

if find "${WGCE_AUDIT_DIR}" -type f \
	! -name '+MANIFEST' ! -name '+COMPACT_MANIFEST' \
	-exec grep -E -n 'OWNER|example\.invalid' {} +; then
	echo 'Publication placeholders remain in the package.' >&2
	exit 1
fi

if find "${WGCE_AUDIT_DIR}" -type f \
	! -name '+MANIFEST' ! -name '+COMPACT_MANIFEST' \
	-exec grep -E -n '%%(PKGVERSION|WGCLIENTEXPORT_VERSION)%%|0\.1\.0-dev' {} +; then
	echo 'Package version placeholders remain in the package.' >&2
	exit 1
fi

echo 'Package structure and secret scan passed.'
