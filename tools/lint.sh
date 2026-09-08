#!/bin/sh

set -eu

WGCE_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
WGCE_PHP_BIN=${WGCE_PHP_BIN:-php}

if ! command -v "${WGCE_PHP_BIN}" >/dev/null 2>&1; then
	echo "PHP runtime not found: ${WGCE_PHP_BIN}" >&2
	exit 1
fi

find "${WGCE_ROOT}/files" "${WGCE_ROOT}/tests" \
	-type f \( -name '*.php' -o -name '*.inc' \) \
	-exec "${WGCE_PHP_BIN}" -l {} \;

if command -v xmllint >/dev/null 2>&1; then
	find "${WGCE_ROOT}/files" -type f -name '*.xml' \
		-exec xmllint --noout {} \;
else
	echo 'xmllint not found; XML validation was not run.' >&2
	exit 1
fi

if command -v shellcheck >/dev/null 2>&1; then
	shellcheck "${WGCE_ROOT}"/tools/*.sh \
		"${WGCE_ROOT}"/files/pkg-install.in \
		"${WGCE_ROOT}"/files/pkg-deinstall.in
else
	echo 'shellcheck not found; shell validation was not run.' >&2
	exit 1
fi

if command -v node >/dev/null 2>&1; then
	node --check \
		"${WGCE_ROOT}/files/usr/local/www/wgclientexport/js/qrcode.js"
else
	echo 'node not found; JavaScript syntax validation was not run.' >&2
	exit 1
fi
