<?php
/*
 * wireguard_adapter.inc
 *
 * The sole mutation boundary with the official pfSense WireGuard package.
 */

function wgclientexport_wireguard_required_functions(): array {
	return array(
		'wg_globals',
		'wg_do_peer_post',
		'wg_tunnel_sync',
		'wg_delete_peer',
		'wg_get_configured_ifs',
		'wg_tunnel_get_config_by_name',
		'wg_tunnel_get_peers_config',
		'wg_tunnel_get_peers_running_keys',
		'wg_gen_keypair',
		'wg_is_service_enabled',
		'wg_is_service_running',
		'is_wg_tunnel_assigned',
		'wg_get_pfsense_interface_info',
		'get_interface_ip',
		'get_interface_subnet',
	);
}

function wgclientexport_wireguard_configured_tunnels(): ?array {
	$names = wg_get_configured_ifs();
	if (!is_array($names)) {
		return null;
	}

	$tunnels = array();
	$seen = array();
	foreach ($names as $name) {
		if (!is_string($name) || !preg_match('/^tun_wg\d+$/D', $name)
		    || isset($seen[$name])) {
			return null;
		}
		$config = wg_tunnel_get_config_by_name($name);
		if (!is_array($config) || !array_key_exists(0, $config)
		    || !isset($config[1]) || !is_array($config[1])
		    || (string) ($config[1]['name'] ?? '') !== $name) {
			return null;
		}
		$seen[$name] = true;
		$tunnels[] = $config[1];
	}
	return $tunnels;
}

function wgclientexport_wireguard_load(bool $require_running = true): array {
	if (!function_exists('wg_globals')) {
		$include = '/usr/local/pkg/wireguard/includes/wg.inc';
		if (!is_file($include)) {
			$include = stream_resolve_include_path('wireguard/includes/wg.inc') ?: '';
		}
		if ($include === '') {
			return array('ready' => false, 'contract' => null, 'input_errors' => array(
				wgclientexport_text('Install and enable the official pfSense WireGuard package first.'),
			));
		}
		require_once($include);
	}

	$missing = array();
	foreach (wgclientexport_wireguard_required_functions() as $function) {
		if (!function_exists($function)) {
			$missing[] = $function;
		}
	}
	if (!empty($missing)) {
		return array('ready' => false, 'contract' => null, 'input_errors' => array(
			wgclientexport_text('The installed WireGuard package exposes an unsupported API contract.'),
		));
	}

	wg_globals();
	if (wgclientexport_wireguard_configured_tunnels() === null) {
		return array('ready' => false, 'contract' => null, 'input_errors' => array(
			wgclientexport_text('The installed WireGuard configuration shape is unsupported.'),
		));
	}
	if ($require_running && (!wg_is_service_enabled() || !wg_is_service_running())) {
		return array('ready' => false, 'contract' => 'wg-0.2-compatible', 'input_errors' => array(
			wgclientexport_text('Enable and start WireGuard before generating a client.'),
		));
	}
	return array('ready' => true, 'contract' => 'wg-0.2-compatible', 'input_errors' => array());
}

function wgclientexport_wireguard_tunnel_addresses(array $tunnel): array {
	$name = (string) ($tunnel['name'] ?? '');
	if (is_wg_tunnel_assigned($name)) {
		$interface = wg_get_pfsense_interface_info($name);
		$interface_name = is_array($interface) ? (string) ($interface['name'] ?? '') : '';
		$address = $interface_name === '' ? '' : (string) get_interface_ip($interface_name);
		$prefix = $interface_name === '' ? '' : (string) get_interface_subnet($interface_name);
		if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
		    || !ctype_digit($prefix) || (int) $prefix < 1 || (int) $prefix > 32) {
			return array('row' => array());
		}
		return array('row' => array(array('address' => $address, 'mask' => $prefix)));
	}

	$rows = $tunnel['addresses']['row'] ?? array();
	if (!is_array($rows)) {
		return array('row' => array());
	}
	if (!empty($rows) && isset($rows['address'])) {
		$rows = array($rows);
	}
	return array('row' => array_values(array_filter($rows, 'is_array')));
}

function wgclientexport_public_tunnel(array $tunnel): ?array {
	$name = (string) ($tunnel['name'] ?? '');
	$public_key = (string) ($tunnel['publickey'] ?? '');
	if (!preg_match('/^tun_wg\d+$/D', $name) || !wgclientexport_valid_wireguard_key($public_key)) {
		return null;
	}
	return array(
		'name' => $name,
		'description' => (string) ($tunnel['descr'] ?? ''),
		'enabled' => (($tunnel['enabled'] ?? 'no') === 'yes'),
		'public_key' => $public_key,
		'listen_port' => (int) ($tunnel['listenport'] ?? 0),
		'addresses' => wgclientexport_wireguard_tunnel_addresses($tunnel),
	);
}

function wgclientexport_list_tunnels(): array {
	$readiness = wgclientexport_wireguard_load(false);
	if (!$readiness['ready']) {
		return array();
	}
	$tunnels = wgclientexport_wireguard_configured_tunnels();
	if ($tunnels === null) {
		return array();
	}
	$result = array();
	foreach ($tunnels as $tunnel) {
		$public = is_array($tunnel) ? wgclientexport_public_tunnel($tunnel) : null;
		if ($public !== null) {
			$result[] = $public;
		}
	}
	return $result;
}

function wgclientexport_wireguard_get_tunnel(string $name): ?array {
	$readiness = wgclientexport_wireguard_load(false);
	if (!$readiness['ready']) {
		return null;
	}
	$config = wg_tunnel_get_config_by_name($name);
	if ($config === false || !isset($config[1]) || !is_array($config[1])) {
		return null;
	}
	return wgclientexport_public_tunnel($config[1]);
}

function wgclientexport_wireguard_get_peers(string $tunnel): array {
	$readiness = wgclientexport_wireguard_load(false);
	if (!$readiness['ready']) {
		return array();
	}
	$peers = array();
	foreach ((array) wg_tunnel_get_peers_config($tunnel) as $entry) {
		if (!is_array($entry) || !isset($entry[0], $entry[1]) || !is_array($entry[1])) {
			continue;
		}
		$peer = $entry[1];
		$peers[] = array(
			'index' => $entry[0],
			'tun' => (string) ($peer['tun'] ?? ''),
			'descr' => (string) ($peer['descr'] ?? ''),
			'enabled' => (string) ($peer['enabled'] ?? 'no'),
			'endpoint' => (string) ($peer['endpoint'] ?? ''),
			'port' => (string) ($peer['port'] ?? ''),
			'publickey' => (string) ($peer['publickey'] ?? ''),
			'allowedips' => is_array($peer['allowedips'] ?? null) ? $peer['allowedips'] : array('row' => array()),
		);
	}
	return $peers;
}

function wgclientexport_build_peer_payload(array $data): array {
	$raw_tunnel = (string) ($data['tunnel'] ?? $data['tun'] ?? '');
	$raw_name = (string) ($data['client_name'] ?? $data['descr'] ?? '');
	$raw_public_key = (string) ($data['public_key'] ?? $data['publickey'] ?? '');
	$raw_address = (string) ($data['address'] ?? '');
	$tunnel = trim($raw_tunnel);
	$name = trim($raw_name);
	$public_key = trim($raw_public_key);
	$address = trim($raw_address);
	if (str_contains($address, '/')) {
		$address = explode('/', $address, 2)[0];
	}
	if (wgclientexport_has_line_break($raw_tunnel) || wgclientexport_has_line_break($raw_name)
	    || wgclientexport_has_line_break($raw_public_key) || wgclientexport_has_line_break($raw_address)
	    || !preg_match('/^tun_wg\d+$/D', $tunnel) || $name === ''
	    || !wgclientexport_valid_wireguard_key($public_key)
	    || !filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
		throw new InvalidArgumentException(wgclientexport_text('Cannot build an invalid WireGuard peer.'));
	}
	return array(
		'index' => null,
		'enabled' => 'yes',
		'tun' => $tunnel,
		'descr' => $name,
		'dynamic' => 'yes',
		'endpoint' => '',
		'port' => '',
		'persistentkeepalive' => '',
		'publickey' => $public_key,
		'presharedkey' => '',
		'address0' => $address,
		'address_subnet0' => '32',
		'address_descr0' => $name,
	);
}

function wgclientexport_wireguard_find_peer(string $tunnel, string $public_key): ?array {
	foreach (wgclientexport_wireguard_get_peers($tunnel) as $peer) {
		if (hash_equals($public_key, $peer['publickey'])) {
			return $peer;
		}
	}
	return null;
}

function wgclientexport_wireguard_generate_keypair(): array {
	$keypair = wg_gen_keypair();
	$private = (string) ($keypair['privkey'] ?? '');
	$public = (string) ($keypair['pubkey'] ?? '');
	if (!wgclientexport_valid_wireguard_key($private) || !wgclientexport_valid_wireguard_key($public)) {
		throw new RuntimeException(wgclientexport_text('WireGuard could not generate a valid client keypair.'));
	}
	return array('private_key' => $private, 'public_key' => $public);
}

function wgclientexport_wireguard_create_peer(array $data): array {
	$payload = wgclientexport_build_peer_payload($data);
	$response = wg_do_peer_post($payload);
	$errors = is_array($response['input_errors'] ?? null) ? $response['input_errors'] : array();
	$changed = !empty($response['changes']);
	$identity = $changed ? array('tunnel' => $payload['tun'],
		'public_key' => $payload['publickey'], 'index' => null) : null;
	if (empty($errors) && $changed) {
		$created = wgclientexport_wireguard_find_peer($payload['tun'], $payload['publickey']);
		if ($created !== null) {
			$identity['index'] = $created['index'];
		} else {
			$errors[] = wgclientexport_text('The new peer could not be confirmed in pfSense configuration.');
		}
	}
	return array('input_errors' => $errors, 'changes' => $changed, 'identity' => $identity);
}

function wgclientexport_wireguard_sync_tunnel(string $tunnel): array {
	if (!wg_is_service_running()) {
		return array('ret_code' => 1, 'tunnels' => array(), 'processed' => false);
	}
	$response = wg_tunnel_sync(array($tunnel), true, true);
	if (!is_array($response)) {
		return array('ret_code' => 1, 'tunnels' => array(), 'processed' => false);
	}
	$processed = false;
	foreach ((array) ($response['tunnels'] ?? array()) as $status) {
		if (($status['name'] ?? '') === $tunnel && (int) ($status['ret_code'] ?? 1) === 0) {
			$processed = true;
			break;
		}
	}
	if (!$processed || !wg_is_service_running()) {
		$response['ret_code'] = ((int) ($response['ret_code'] ?? 0)) | 1;
	}
	$response['processed'] = $processed;
	return $response;
}

function wgclientexport_wireguard_running_peer_exists(string $tunnel, string $public_key): bool {
	if (!wg_is_service_running()) {
		return false;
	}
	$keys = array_map('trim', (array) wg_tunnel_get_peers_running_keys($tunnel));
	return in_array($public_key, $keys, true);
}

function wgclientexport_wireguard_delete_peer(array $identity): array {
	$tunnel = (string) ($identity['tunnel'] ?? '');
	$public_key = (string) ($identity['public_key'] ?? '');
	$peer = wgclientexport_wireguard_find_peer($tunnel, $public_key);
	if ($peer === null) {
		return array('input_errors' => array(), 'changes' => false, 'persistent_absent' => true);
	}
	$response = wg_delete_peer($peer['index']);
	if (!is_array($response)) {
		return array('input_errors' => array(
			wgclientexport_text('The WireGuard peer deletion returned an invalid result.')),
			'changes' => false, 'persistent_absent' => false);
	}
	$response['persistent_absent'] = wgclientexport_wireguard_find_peer($tunnel, $public_key) === null;
	return $response;
}

function wgclientexport_wireguard_confirm_peer(array $identity, string $address): bool {
	$peer = wgclientexport_wireguard_find_peer(
		(string) ($identity['tunnel'] ?? ''),
		(string) ($identity['public_key'] ?? '')
	);
	if ($peer === null || $peer['endpoint'] !== '' || $peer['port'] !== '') {
		return false;
	}
	return wgclientexport_find_duplicate_allowed_ip(array($address . '/32'), array($peer)) !== null
		&& wgclientexport_wireguard_running_peer_exists($identity['tunnel'], $identity['public_key']);
}

function wgclientexport_wireguard_confirm_peer_absent(array $identity): bool {
	$tunnel = (string) ($identity['tunnel'] ?? '');
	$public_key = (string) ($identity['public_key'] ?? '');
	if (!wg_is_service_running()) {
		return false;
	}
	$running_keys = array_map('trim', (array) wg_tunnel_get_peers_running_keys($tunnel));
	return wgclientexport_wireguard_find_peer($tunnel, $public_key) === null
		&& !in_array($public_key, $running_keys, true);
}
