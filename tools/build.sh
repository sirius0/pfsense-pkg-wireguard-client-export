#!/bin/sh

set -eu

WGCE_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

if [ "$(uname -s)" != 'FreeBSD' ]; then
	echo 'A FreeBSD/pfSense ports environment is required to build the package.' >&2
	exit 1
fi

if ! command -v portlint >/dev/null 2>&1; then
	echo 'portlint is required. Install it from ports-mgmt/portlint.' >&2
	exit 1
fi

cd "${WGCE_ROOT}"
portlint -CN
make check-plist
make package

WGCE_PKGNAME=$(make -V PKGNAME)
WGCE_PACKAGE="${WGCE_ROOT}/work/pkg/${WGCE_PKGNAME}.pkg"
if [ ! -f "${WGCE_PACKAGE}" ]; then
	WGCE_PACKAGE="${WGCE_ROOT}/work/pkg/${WGCE_PKGNAME}.txz"
fi

"${WGCE_ROOT}/tools/package-audit.sh" "${WGCE_PACKAGE}"
