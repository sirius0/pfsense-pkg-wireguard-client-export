<?php
/*
 * bootstrap.inc
 *
 * Package entry point. Definitions are safe to load before WireGuard starts.
 */

if (!defined('WGCLIENTEXPORT_VERSION')) {
	define('WGCLIENTEXPORT_VERSION', '%%WGCLIENTEXPORT_VERSION%%');
}

if (!function_exists('config_get_path') && is_file('/etc/inc/config.inc')) {
	require_once('/etc/inc/config.inc');
}

require_once(__DIR__ . '/validation.inc');
require_once(__DIR__ . '/config.inc');
require_once(__DIR__ . '/ip_allocator.inc');
require_once(__DIR__ . '/client_config.inc');
require_once(__DIR__ . '/wireguard_adapter.inc');
require_once(__DIR__ . '/provisioner.inc');

function wgclientexport_bootstrap(): array {
	if (!function_exists('config_get_path') || !function_exists('config_set_path')
	    || !function_exists('write_config')) {
		return array(
			'ready' => false,
			'contract' => null,
			'input_errors' => array(wgclientexport_text('The pfSense configuration API is unavailable.')),
		);
	}
	return wgclientexport_wireguard_load();
}

function wgclientexport_install(): array {
	if (!function_exists('config_get_path') || !function_exists('config_set_path')
	    || !function_exists('write_config')) {
		throw new RuntimeException(
			wgclientexport_text('The pfSense configuration API is unavailable.'));
	}

	$current = config_get_path(WGCLIENTEXPORT_CONFIG_PATH, null);
	if (is_array($current) && !wgclientexport_settings_schema_is_supported($current)) {
		throw new RuntimeException(wgclientexport_text(
			'The stored Client Export settings use an unsupported schema version.'));
	}
	$normalized_current = is_array($current)
		? wgclientexport_normalize_stored_settings($current) : null;
	if ($normalized_current !== null) {
		$normalized = wgclientexport_save_settings(array(
			'tunnels' => $normalized_current['tunnels']['item'],
		));
		if (!empty($normalized['input_errors'])) {
			throw new RuntimeException(wgclientexport_text(
				'Existing Client Export settings could not be migrated safely.'));
		}
		return array('input_errors' => $normalized['input_errors'], 'result' => $normalized['result'],
			'changes' => $normalized['changes']);
	}
	$empty_legacy_array = is_array($current)
		&& array_diff(array_keys($current), array('schema_version', 'tunnels')) === array()
		&& (!array_key_exists('tunnels', $current)
			|| $current['tunnels'] === null || $current['tunnels'] === '1');
	$repairable = $current === null || $current === '' || $current === '1'
		|| $current === array() || $empty_legacy_array
		|| (is_array($current) && wgclientexport_contains_secret_field($current));
	if (!$repairable) {
		throw new RuntimeException(wgclientexport_text(
			'Existing Client Export settings could not be migrated safely.'));
	}
	$settings = wgclientexport_default_settings();
	if (!wgclientexport_persist_settings($settings,
	    wgclientexport_text('Initialized WireGuard Client Export settings.'))) {
		throw new RuntimeException(
			wgclientexport_text('Client Export settings could not be initialized.'));
	}
	return array('input_errors' => array(), 'result' => $settings, 'changes' => true);
}

function wgclientexport_deinstall(): array {
	/*
	 * Deliberately preserve package-owned, non-secret preferences. Official
	 * WireGuard tunnels and peers are never touched by deinstallation.
	 */
	return array(
		'input_errors' => array(),
		'result' => array('settings_preserved' => true),
		'changes' => false,
	);
}
