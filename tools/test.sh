#!/bin/sh

set -eu

WGCE_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
WGCE_PHP_BIN=${WGCE_PHP_BIN:-php}

if ! command -v "${WGCE_PHP_BIN}" >/dev/null 2>&1; then
	echo "PHP runtime not found: ${WGCE_PHP_BIN}" >&2
	exit 1
fi

for WGCE_TEST_FILE in \
	"${WGCE_ROOT}/tests/ip_allocator_test.php" \
	"${WGCE_ROOT}/tests/client_config_test.php" \
	"${WGCE_ROOT}/tests/validation_test.php" \
	"${WGCE_ROOT}/tests/config_test.php" \
	"${WGCE_ROOT}/tests/provisioner_test.php" \
	"${WGCE_ROOT}/tests/wireguard_0_2_1_contract_test.php" \
	"${WGCE_ROOT}/tests/wireguard_current_contract_test.php"
do
	"${WGCE_PHP_BIN}" "${WGCE_TEST_FILE}"
done
