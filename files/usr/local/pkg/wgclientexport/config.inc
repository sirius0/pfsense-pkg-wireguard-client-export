<?php
/*
 * config.inc
 *
 * Non-secret companion settings stored through pfSense configuration APIs.
 */

if (!defined('WGCLIENTEXPORT_CONFIG_PATH')) {
	define('WGCLIENTEXPORT_CONFIG_PATH', 'installedpackages/wgclientexport/config/0');
}

function wgclientexport_default_settings(): array {
	return array(
		'schema_version' => '1',
		'tunnels' => array('item' => array()),
	);
}

function wgclientexport_settings_schema_is_supported(array $settings): bool {
	if (!array_key_exists('schema_version', $settings)) {
		return true;
	}
	$version = $settings['schema_version'];
	return (is_string($version) || is_int($version)) && (string) $version === '1';
}

function wgclientexport_sanitize_tunnel_setting(array $settings): array {
	return array_intersect_key($settings, array_flip(array(
		'tunnel_id',
		'enabled',
		'client_pool_ipv4',
		'endpoint_host',
		'endpoint_port',
		'dns_ipv4',
		'persistent_keepalive',
		'local_routes_ipv4',
		'reservations_ipv4',
	)));
}

function wgclientexport_stored_tunnel_items(array $settings): ?array {
	if (!array_key_exists('tunnels', $settings)) {
		return null;
	}
	$tunnels = $settings['tunnels'];
	if ($tunnels === '') {
		return array();
	}
	if (!is_array($tunnels) || !array_key_exists('item', $tunnels)) {
		return null;
	}
	$items = $tunnels['item'];
	if ($items === '' || $items === null || $items === array()) {
		return array();
	}
	if (!is_array($items)) {
		return null;
	}
	if (!array_is_list($items)) {
		return wgclientexport_sanitize_tunnel_setting($items) === array()
			? null : array($items);
	}
	return $items;
}

function wgclientexport_normalize_stored_settings(array $settings): ?array {
	if (!wgclientexport_settings_schema_is_supported($settings)) {
		return null;
	}
	$stored_items = wgclientexport_stored_tunnel_items($settings);
	if ($stored_items === null) {
		return null;
	}

	$items = array();
	foreach ($stored_items as $item) {
		if (!is_array($item)) {
			return null;
		}
		$normalized = wgclientexport_normalize_tunnel_settings(
			wgclientexport_sanitize_tunnel_setting($item));
		if (!empty($normalized['input_errors'])) {
			return null;
		}
		$items[] = $normalized['result'];
	}
	return array('schema_version' => '1', 'tunnels' => array('item' => $items));
}

function wgclientexport_get_settings(): array {
	if (!function_exists('config_get_path')) {
		return wgclientexport_default_settings();
	}
	$settings = config_get_path(WGCLIENTEXPORT_CONFIG_PATH, null);
	if (!is_array($settings)) {
		return wgclientexport_default_settings();
	}
	$normalized = wgclientexport_normalize_stored_settings($settings);
	return $normalized ?? wgclientexport_default_settings();
}

function wgclientexport_get_tunnel_settings(string $tunnel): ?array {
	$settings = wgclientexport_get_settings();
	foreach ($settings['tunnels']['item'] as $item) {
		if (is_array($item) && ($item['tunnel_id'] ?? '') === $tunnel) {
			return $item;
		}
	}
	return null;
}

function wgclientexport_suggest_pool_from_tunnel(array $tunnel): string {
	$rows = $tunnel['addresses']['row'] ?? $tunnel['addresses'] ?? array();
	if (is_array($rows) && isset($rows['address'])) {
		$rows = array($rows);
	}
	foreach ((array) $rows as $row) {
		if (is_array($row)) {
			$address = trim((string) ($row['address'] ?? ''));
			$mask = trim((string) ($row['mask'] ?? ''));
			$candidate = $address !== '' && $mask !== '' ? $address . '/' . $mask : '';
		} else {
			$candidate = trim((string) $row);
		}
		$parsed = wgclientexport_parse_ipv4_cidr($candidate);
		if ($parsed !== null && $parsed['prefix'] <= 30) {
			return $parsed['cidr'];
		}
	}
	return '';
}

function wgclientexport_suggestion_dns_is_usable(mixed $value): bool {
	if (!is_string($value)) {
		return false;
	}
	$address = trim($value);
	if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
		return false;
	}
	$octets = array_map('intval', explode('.', $address));
	return $octets[0] !== 0 && $octets[0] !== 127 && $octets[0] < 224
		&& !($octets[0] === 169 && $octets[1] === 254);
}

function wgclientexport_suggest_dns_ipv4(mixed $configured): array {
	$result = array();
	$visit = static function (mixed $value) use (&$visit, &$result): void {
		if (is_array($value)) {
			foreach ($value as $item) {
				$visit($item);
			}
			return;
		}
		if (!wgclientexport_suggestion_dns_is_usable($value)) {
			return;
		}
		$address = trim((string) $value);
		if (!in_array($address, $result, true)
		    && count($result) < WGCLIENTEXPORT_MAX_DNS_SERVERS) {
			$result[] = $address;
		}
	};
	$visit($configured);
	return $result;
}

function wgclientexport_suggest_ddns_hosts(mixed $records): array {
	$result = array();
	$visit = static function (mixed $value) use (&$visit, &$result): void {
		if (is_string($value)) {
			$host = strtolower(trim($value));
			if (filter_var($host, FILTER_VALIDATE_IP) === false
			    && wgclientexport_valid_endpoint_host($host)
			    && !in_array($host, $result, true)) {
				$result[] = $host;
			}
			return;
		}
		if (!is_array($value)) {
			return;
		}
		/* pfSense stores a present enable key when the DDNS row is disabled. */
		$disabled = isset($value['disabled']) || isset($value['enable']);
		if ($disabled) {
			return;
		}
		foreach (array('host', 'hostname', 'domainname') as $key) {
			if (array_key_exists($key, $value)) {
				$visit($value[$key]);
				return;
			}
		}
		foreach ($value as $item) {
			$visit($item);
		}
	};
	$visit($records);
	return $result;
}

function wgclientexport_suggestion_ipv4_is_public(mixed $value): bool {
	if (!is_string($value)) {
		return false;
	}
	$address = trim($value);
	if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
		return false;
	}
	$non_public_ranges = array(
		'0.0.0.0/8',
		'10.0.0.0/8',
		'100.64.0.0/10',
		'127.0.0.0/8',
		'169.254.0.0/16',
		'172.16.0.0/12',
		'192.0.0.0/24',
		'192.0.2.0/24',
		'192.88.99.0/24',
		'192.168.0.0/16',
		'198.18.0.0/15',
		'198.51.100.0/24',
		'203.0.113.0/24',
		'224.0.0.0/4',
		'240.0.0.0/4',
	);
	foreach ($non_public_ranges as $range) {
		if (wgclientexport_ipv4_in_cidr($address, $range)) {
			return false;
		}
	}
	return true;
}

function wgclientexport_suggest_endpoint_host(mixed $ddns_records,
    mixed $wan_ipv4): string {
	$hosts = wgclientexport_suggest_ddns_hosts($ddns_records);
	if (count($hosts) === 1) {
		return $hosts[0];
	}
	$wan = is_string($wan_ipv4) ? trim($wan_ipv4) : '';
	if (wgclientexport_suggestion_ipv4_is_public($wan)) {
		return $wan;
	}
	return '';
}

function wgclientexport_suggest_local_routes(mixed $networks): array {
	$result = array();
	$visit = static function (mixed $value) use (&$visit, &$result): void {
		if (is_array($value) && isset($value['address'], $value['mask'])) {
			$candidate = trim((string) $value['address']) . '/'
				. trim((string) $value['mask']);
		} elseif (is_array($value)) {
			foreach ($value as $item) {
				$visit($item);
			}
			return;
		} else {
			$candidate = trim((string) $value);
		}
		$parsed = wgclientexport_parse_ipv4_cidr($candidate);
		if ($parsed === null || $parsed['prefix'] === 0) {
			return;
		}
		$cidr = $parsed['cidr'];
		if (!in_array($cidr, $result, true) && count($result) < WGCLIENTEXPORT_MAX_ROUTES) {
			$result[] = $cidr;
		}
	};
	$visit($networks);
	return $result;
}

/*
 * Pure, non-persisting suggestions. $context accepts dns_servers,
 * ddns_records, wan_ipv4 and local_networks snapshots collected by the page.
 */
function wgclientexport_suggest_tunnel_settings(array $tunnel,
    array $context = array()): array {
	$port = (string) ($tunnel['listen_port'] ?? $tunnel['listenport'] ?? '');
	if (!ctype_digit($port) || (int) $port < 1 || (int) $port > 65535) {
		$port = '';
	} else {
		$port = (string) (int) $port;
	}
	return array(
		'tunnel_id' => (string) ($tunnel['name'] ?? ''),
		'enabled' => 'yes',
		'client_pool_ipv4' => wgclientexport_suggest_pool_from_tunnel($tunnel),
		'endpoint_host' => wgclientexport_suggest_endpoint_host(
			$context['ddns_records'] ?? array(), $context['wan_ipv4'] ?? ''),
		'endpoint_port' => $port,
		'dns_ipv4' => array('item' => wgclientexport_suggest_dns_ipv4(
			$context['dns_servers'] ?? array())),
		'persistent_keepalive' => '25',
		'local_routes_ipv4' => array('item' => wgclientexport_suggest_local_routes(
			$context['local_networks'] ?? array())),
		'reservations_ipv4' => array('item' => array()),
	);
}

/* Stored settings win as a complete row, including deliberately empty fields. */
function wgclientexport_settings_for_ui(array $tunnel, array $context = array(),
    ?array $stored = null): array {
	return $stored === null
		? wgclientexport_suggest_tunnel_settings($tunnel, $context)
		: wgclientexport_sanitize_tunnel_setting($stored);
}

function wgclientexport_contains_secret_field(array $value): bool {
	foreach ($value as $key => $item) {
		$name = strtolower((string) $key);
		if (preg_match('/(?:private.?key|preshared|pre.?shared|\bpsk\b|configuration|qr.?payload|secret)/', $name)) {
			return true;
		}
		if (is_array($item) && wgclientexport_contains_secret_field($item)) {
			return true;
		}
	}
	return false;
}

function wgclientexport_normalize_tunnel_settings(array $input): array {
	$errors = array();
	$raw_tunnel = (string) ($input['tunnel_id'] ?? $input['tunnel'] ?? $input['tun'] ?? '');
	$raw_pool = (string) ($input['client_pool_ipv4'] ?? $input['pool'] ?? '');
	$raw_host = (string) ($input['endpoint_host'] ?? '');
	$tunnel = trim($raw_tunnel);
	$pool = trim($raw_pool);
	$host = trim($raw_host);
	$port = (string) ($input['endpoint_port'] ?? '');
	$keepalive = (string) ($input['persistent_keepalive'] ?? '25');
	$parsed_pool = wgclientexport_parse_ipv4_cidr($pool);

	if (wgclientexport_has_line_break($raw_tunnel) || !preg_match('/^tun_wg\d+$/D', $tunnel)) {
		$errors[] = wgclientexport_text('Select a valid WireGuard tunnel.');
	}
	if ($parsed_pool === null || $parsed_pool['prefix'] > 30) {
		$errors[] = wgclientexport_text('The client pool must be a valid IPv4 network with at least four addresses.');
	}
	if (wgclientexport_has_line_break($raw_host) || !wgclientexport_valid_endpoint_host($host)) {
		$errors[] = wgclientexport_text('The endpoint must be a valid hostname or IPv4 address.');
	}
	if (!ctype_digit($port) || (int) $port < 1 || (int) $port > 65535) {
		$errors[] = wgclientexport_text('The endpoint port must be between 1 and 65535.');
	}
	if ($keepalive === '' || !ctype_digit($keepalive) || (int) $keepalive > 65535) {
		$errors[] = wgclientexport_text('Persistent keepalive must be between 0 and 65535.');
	}

	$dns = array();
	foreach (wgclientexport_normalize_list($input['dns_ipv4'] ?? $input['dns'] ?? array()) as $resolver) {
		$resolver = trim((string) $resolver);
		if (!filter_var($resolver, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$errors[] = wgclientexport_text('Every DNS resolver must be a valid IPv4 address.');
			break;
		}
		if (!in_array($resolver, $dns, true)) {
			$dns[] = $resolver;
		}
	}
	if (count($dns) > WGCLIENTEXPORT_MAX_DNS_SERVERS) {
		$errors[] = wgclientexport_text('Client Export settings can contain at most four DNS resolvers.');
	}

	$local_routes = $reservations = array();
	try {
		$local_routes = wgclientexport_normalize_ipv4_cidrs(
			wgclientexport_normalize_list($input['local_routes_ipv4'] ?? $input['local_networks'] ?? array())
		);
	} catch (InvalidArgumentException $exception) {
		$errors[] = $exception->getMessage();
	}
	if (count($local_routes) > WGCLIENTEXPORT_MAX_ROUTES) {
		$errors[] = wgclientexport_text('Client Export settings can contain at most 32 local routes.');
	}
	foreach (wgclientexport_normalize_list($input['reservations_ipv4'] ?? $input['reservations'] ?? array()) as $reservation) {
		$reservation = trim((string) $reservation);
		if (!filter_var($reservation, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
		    || $parsed_pool === null || !wgclientexport_ipv4_in_cidr($reservation, $parsed_pool['cidr'])
		    || $reservation === $parsed_pool['network'] || $reservation === $parsed_pool['broadcast']) {
			$errors[] = wgclientexport_text('Every reservation must be a usable IPv4 address inside the client pool.');
			break;
		}
		if (!in_array($reservation, $reservations, true)) {
			$reservations[] = $reservation;
		}
	}

	$normalized = array(
		'tunnel_id' => $tunnel,
		'enabled' => (($input['enabled'] ?? 'no') === 'yes') ? 'yes' : 'no',
		'client_pool_ipv4' => $parsed_pool['cidr'] ?? $pool,
		'endpoint_host' => strtolower($host),
		'endpoint_port' => ctype_digit($port) ? (string) (int) $port : $port,
		'dns_ipv4' => array('item' => $dns),
		'persistent_keepalive' => ctype_digit($keepalive) ? (string) (int) $keepalive : $keepalive,
		'local_routes_ipv4' => array('item' => $local_routes),
		'reservations_ipv4' => array('item' => $reservations),
	);
	return array('input_errors' => array_values(array_unique($errors)), 'result' => $normalized);
}

function wgclientexport_settings_items_from_post(array $post): array {
	if (isset($post['tunnels']['item']) && is_array($post['tunnels']['item'])) {
		return $post['tunnels']['item'];
	}
	if (isset($post['tunnels']) && is_array($post['tunnels'])) {
		return $post['tunnels'];
	}
	return array($post);
}

function wgclientexport_persist_settings(array $settings, string $description): bool {
	$set_result = config_set_path(WGCLIENTEXPORT_CONFIG_PATH, $settings);
	if ($set_result === false || $set_result === -1) {
		return false;
	}
	$write_result = write_config($description);
	return $write_result !== false && $write_result !== -1;
}

function wgclientexport_save_settings(array $post): array {
	if (wgclientexport_contains_secret_field($post)) {
		return array(
			'input_errors' => array(wgclientexport_text('Secret material cannot be stored in Client Export settings.')),
			'saved' => false,
			'changes' => false,
			'result' => null,
		);
	}
	if (!function_exists('config_get_path') || !function_exists('config_set_path')
	    || !function_exists('write_config')) {
		return array('input_errors' => array(wgclientexport_text('The pfSense configuration API is unavailable.')),
			'saved' => false, 'changes' => false, 'result' => null);
	}
	$current = config_get_path(WGCLIENTEXPORT_CONFIG_PATH, null);
	if (is_array($current) && !wgclientexport_settings_schema_is_supported($current)) {
		return array('input_errors' => array(
			wgclientexport_text('The stored Client Export settings use an unsupported schema version.')),
			'saved' => false, 'changes' => false, 'result' => null);
	}
	$current_normalized = is_array($current)
		? wgclientexport_normalize_stored_settings($current) : null;
	$current_contains_secret = is_array($current) && wgclientexport_contains_secret_field($current);

	$explicit_collection = isset($post['tunnels']) && is_array($post['tunnels']);
	$errors = $items = $seen = array();
	if (!$explicit_collection) {
		$existing_settings = $current_normalized ?? wgclientexport_default_settings();
		foreach ($existing_settings['tunnels']['item'] as $existing) {
			if (!is_array($existing) || wgclientexport_contains_secret_field($existing)) {
				$errors[] = wgclientexport_text('Existing Client Export settings contain unsupported or secret fields.');
				continue;
			}
			$normalized = wgclientexport_normalize_tunnel_settings($existing);
			$errors = array_merge($errors, $normalized['input_errors']);
			$id = $normalized['result']['tunnel_id'];
			if ($id !== '') {
				$items[$id] = $normalized['result'];
			}
		}
	}
	foreach (wgclientexport_settings_items_from_post($post) as $input) {
		if (!is_array($input)) {
			$errors[] = wgclientexport_text('Tunnel settings are invalid.');
			continue;
		}
		$normalized = wgclientexport_normalize_tunnel_settings($input);
		$errors = array_merge($errors, $normalized['input_errors']);
		$id = $normalized['result']['tunnel_id'];
		if ($id !== '' && isset($seen[$id])) {
			$errors[] = wgclientexport_text('A tunnel can have only one Client Export settings entry.');
		}
		$seen[$id] = true;
		$items[$id] = $normalized['result'];
	}
	if (!empty($errors)) {
		return array('input_errors' => array_values(array_unique($errors)), 'saved' => false,
			'changes' => false, 'result' => null);
	}
	$settings = array('schema_version' => '1', 'tunnels' => array('item' => array_values($items)));
	$changes = $settings !== $current_normalized || $current_contains_secret;
	if ($changes && !wgclientexport_persist_settings($settings,
	    wgclientexport_text('Saved WireGuard Client Export settings.'))) {
		return array('input_errors' => array(wgclientexport_text('Client Export settings could not be saved.')),
			'saved' => false, 'changes' => false, 'result' => null);
	}
	return array('input_errors' => array(), 'saved' => true, 'changes' => $changes, 'result' => $settings);
}
