#!/bin/sh

set -eu

WGCE_SOURCE_ROOT=${1:-}
WGCE_OUTPUT_DIR=${2:-}
WGCE_VERSION=${WGCE_PACKAGE_VERSION:-${WGCE_TEST_VERSION:-0.1.0.b1}}
WGCE_PACKAGE_NAME='pfSense-pkg-WireGuard-ClientExport'

if [ "$(uname -s)" != 'FreeBSD' ]; then
	echo 'This package builder must run on FreeBSD/pfSense.' >&2
	exit 1
fi
if [ -z "${WGCE_SOURCE_ROOT}" ] || [ ! -f "${WGCE_SOURCE_ROOT}/pkg-plist" ]; then
	echo 'Usage: build-test-package.sh SOURCE_ROOT OUTPUT_DIR' >&2
	exit 64
fi
case "${WGCE_SOURCE_ROOT}" in
	/tmp/*) ;;
	*)
		echo 'The package source root must be under /tmp.' >&2
		exit 64
		;;
esac
if [ -z "${WGCE_OUTPUT_DIR}" ]; then
	echo 'Usage: build-test-package.sh SOURCE_ROOT OUTPUT_DIR' >&2
	exit 64
fi
case "${WGCE_OUTPUT_DIR}" in
	/tmp/*) ;;
	*)
		echo 'The package output directory must be under /tmp.' >&2
		exit 64
		;;
esac
case "${WGCE_VERSION}" in
	''|*[!0-9A-Za-z._-]*)
		echo 'The package version contains unsupported characters.' >&2
		exit 64
		;;
esac

for WGCE_REQUIRED_TOOL in pkg php install mktemp sed
do
	if ! command -v "${WGCE_REQUIRED_TOOL}" >/dev/null 2>&1; then
		echo "Required tool not found: ${WGCE_REQUIRED_TOOL}" >&2
		exit 69
	fi
done

if ! pkg info -e 'pfSense-pkg-WireGuard-0.2.1'; then
	echo 'The package builder requires pfSense-pkg-WireGuard-0.2.1.' >&2
	exit 69
fi

mkdir -p "${WGCE_OUTPUT_DIR}"
WGCE_WORK_DIR=$(mktemp -d -t wgclientexport-package.XXXXXX)
WGCE_STAGE_DIR="${WGCE_WORK_DIR}/stage"
WGCE_METADATA_DIR="${WGCE_WORK_DIR}/metadata"
WGCE_GENERATED_PLIST="${WGCE_WORK_DIR}/pkg-plist"

cleanup_wgce_build() {
	case "${WGCE_WORK_DIR}" in
		/tmp/wgclientexport-package.*)
			rm -rf -- "${WGCE_WORK_DIR}"
			;;
	esac
}

trap cleanup_wgce_build EXIT HUP INT TERM

mkdir -p "${WGCE_STAGE_DIR}" "${WGCE_METADATA_DIR}"
: > "${WGCE_GENERATED_PLIST}"

while IFS= read -r WGCE_PLIST_ENTRY
do
	case "${WGCE_PLIST_ENTRY}" in
		''|'@dir '*) continue ;;
		/etc/*)
			WGCE_PACKAGE_PATH=${WGCE_PLIST_ENTRY}
			WGCE_SOURCE_PATH="${WGCE_SOURCE_ROOT}/files${WGCE_PACKAGE_PATH}"
			;;
		'%%DATADIR%%/THIRD_PARTY_NOTICES.md')
			WGCE_PACKAGE_PATH='/usr/local/share/pfSense-pkg-WireGuard-ClientExport/THIRD_PARTY_NOTICES.md'
			WGCE_SOURCE_PATH="${WGCE_SOURCE_ROOT}/THIRD_PARTY_NOTICES.md"
			;;
		'%%DATADIR%%/LICENSE')
			WGCE_PACKAGE_PATH='/usr/local/share/pfSense-pkg-WireGuard-ClientExport/LICENSE'
			WGCE_SOURCE_PATH="${WGCE_SOURCE_ROOT}/LICENSE"
			;;
		'%%DATADIR%%/'*)
			WGCE_SUFFIX=${WGCE_PLIST_ENTRY#%%DATADIR%%/}
			WGCE_PACKAGE_PATH="/usr/local/share/pfSense-pkg-WireGuard-ClientExport/${WGCE_SUFFIX}"
			WGCE_SOURCE_PATH="${WGCE_SOURCE_ROOT}/files${WGCE_PACKAGE_PATH}"
			;;
		*)
			WGCE_PACKAGE_PATH="/usr/local/${WGCE_PLIST_ENTRY}"
			WGCE_SOURCE_PATH="${WGCE_SOURCE_ROOT}/files${WGCE_PACKAGE_PATH}"
			;;
	esac
	case "${WGCE_PACKAGE_PATH}" in
		*..*|*//*|*\\*)
			echo "Unsafe package path: ${WGCE_PACKAGE_PATH}" >&2
			exit 65
			;;
		/etc/inc/priv/wgclientexport.priv.inc) ;;
		/usr/local/pkg/wgclientexport.xml) ;;
		/usr/local/pkg/wgclientexport/*.inc) ;;
		/usr/local/www/wgclientexport/vpn_wg_client_export.php) ;;
		/usr/local/www/wgclientexport/js/qrcode.js) ;;
		/usr/local/share/pfSense-pkg-WireGuard-ClientExport/info.xml) ;;
		/usr/local/share/pfSense-pkg-WireGuard-ClientExport/LICENSE) ;;
		/usr/local/share/pfSense-pkg-WireGuard-ClientExport/THIRD_PARTY_NOTICES.md) ;;
		*)
			echo "Unexpected package path: ${WGCE_PACKAGE_PATH}" >&2
			exit 65
			;;
	esac

	if [ ! -f "${WGCE_SOURCE_PATH}" ]; then
		echo "Missing source for package path: ${WGCE_PACKAGE_PATH}" >&2
		exit 66
	fi
	WGCE_DESTINATION="${WGCE_STAGE_DIR}${WGCE_PACKAGE_PATH}"
	mkdir -p "$(dirname -- "${WGCE_DESTINATION}")"
	install -m 0644 "${WGCE_SOURCE_PATH}" "${WGCE_DESTINATION}"
	printf '%s\n' "${WGCE_PACKAGE_PATH}" >> "${WGCE_GENERATED_PLIST}"
done < "${WGCE_SOURCE_ROOT}/pkg-plist"

sed -i '' \
	-e "s|%%PKGVERSION%%|${WGCE_VERSION}|g" \
	"${WGCE_STAGE_DIR}/usr/local/pkg/wgclientexport.xml" \
	"${WGCE_STAGE_DIR}/usr/local/share/pfSense-pkg-WireGuard-ClientExport/info.xml"
sed -i '' \
	-e "s|%%WGCLIENTEXPORT_VERSION%%|${WGCE_VERSION}|g" \
	"${WGCE_STAGE_DIR}/usr/local/pkg/wgclientexport/bootstrap.inc"

WGCE_MANIFEST_PATH="${WGCE_METADATA_DIR}/+MANIFEST"
# PHP variables in the following single-quoted program must not expand here.
# shellcheck disable=SC2016
/usr/local/bin/php -r '
$path = $argv[1];
$version = $argv[2];
$manifest = array(
    "name" => "pfSense-pkg-WireGuard-ClientExport",
    "origin" => "net/pfSense-pkg-WireGuard-ClientExport",
    "version" => $version,
    "comment" => "Minimal WireGuard remote-access client provisioning for pfSense",
    "maintainer" => "sirius0@users.noreply.github.com",
    "www" => "https://github.com/sirius0/pfsense-pkg-wireguard-client-export",
    "abi" => "FreeBSD:14:amd64",
    "arch" => "freebsd:14:x86:64",
    "prefix" => "/",
    "flatsize" => 0,
    "licenselogic" => "single",
    "licenses" => array("APACHE20"),
    "desc" => "WireGuard Client Export companion for one-time client configuration and QR-code generation.",
    "deps" => array(
        "pfSense-pkg-WireGuard" => array(
            "origin" => "net/pfSense-pkg-WireGuard",
            "version" => "0.2.1"
        )
    ),
    "scripts" => array(
        "post-install" => "/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-WireGuard-ClientExport POST-INSTALL",
        "pre-deinstall" => "/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-WireGuard-ClientExport DEINSTALL",
        "post-deinstall" => "/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-WireGuard-ClientExport POST-DEINSTALL"
    )
);
$encoded = json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
if ($encoded === false || file_put_contents($path, $encoded . PHP_EOL) === false) {
    fwrite(STDERR, "Unable to write package manifest.\n");
    exit(1);
}
' "${WGCE_MANIFEST_PATH}" "${WGCE_VERSION}"

pkg create -f txz -o "${WGCE_OUTPUT_DIR}" \
	-r "${WGCE_STAGE_DIR}" -m "${WGCE_METADATA_DIR}" \
	-p "${WGCE_GENERATED_PLIST}"

WGCE_PACKAGE_PATH="${WGCE_OUTPUT_DIR}/${WGCE_PACKAGE_NAME}-${WGCE_VERSION}.pkg"
if [ ! -f "${WGCE_PACKAGE_PATH}" ]; then
	echo "Expected package not found: ${WGCE_PACKAGE_PATH}" >&2
	exit 70
fi

pkg info -F "${WGCE_PACKAGE_PATH}" >/dev/null
sha256 -q "${WGCE_PACKAGE_PATH}"
printf '%s\n' "${WGCE_PACKAGE_PATH}"
