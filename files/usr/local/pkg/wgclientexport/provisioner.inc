<?php
/*
 * provisioner.inc
 *
 * Locked application-level transaction for one-time client provisioning.
 */

function wgclientexport_failure(string $code, string $message, ?bool $rollback = null): array {
	return array(
		'input_errors' => array($message),
		'error_code' => $code,
		'changes' => false,
		'rollback' => $rollback,
		'result' => null,
	);
}

function wgclientexport_dependency(array $deps, string $name, callable $default): callable {
	return isset($deps[$name]) && is_callable($deps[$name]) ? $deps[$name] : $default;
}

function wgclientexport_provision_settings(string $tunnel, array $deps): ?array {
	if (isset($deps['settings'])) {
		return is_callable($deps['settings']) ? ($deps['settings'])($tunnel) : $deps['settings'];
	}
	return wgclientexport_get_tunnel_settings($tunnel);
}

function wgclientexport_merge_provision_request(array $request, array $settings): array {
	return array(
		'tunnel' => (string) ($request['tunnel'] ?? $request['tun'] ?? ''),
		'client_name' => (string) ($request['client_name'] ?? $request['name'] ?? $request['descr'] ?? ''),
		'pool' => (string) ($settings['client_pool_ipv4'] ?? $settings['pool'] ?? ''),
		'endpoint_host' => (string) ($settings['endpoint_host'] ?? ''),
		'endpoint_port' => (string) ($settings['endpoint_port'] ?? ''),
		'routing_profile' => (string) ($request['routing_profile'] ?? $request['access_mode'] ?? ''),
		'local_routes_ipv4' => wgclientexport_normalize_list(
			$settings['local_routes_ipv4'] ?? $settings['local_networks'] ?? array()
		),
		'custom_routes_ipv4' => wgclientexport_normalize_list(
			$request['custom_routes_ipv4'] ?? $request['custom_allowed_ips'] ?? array()
		),
		'dns_ipv4' => wgclientexport_normalize_list(
			array_key_exists('dns_ipv4', $request) || array_key_exists('dns', $request)
				? ($request['dns_ipv4'] ?? $request['dns'])
				: ($settings['dns_ipv4'] ?? $settings['dns'] ?? array())
		),
		'persistent_keepalive' => (string) (
			$request['persistent_keepalive'] ?? $request['persistentkeepalive']
			?? $settings['persistent_keepalive'] ?? '0'
		),
		'client_address' => (string) ($request['client_address'] ?? $request['address'] ?? ''),
		'reservations_ipv4' => wgclientexport_normalize_list(
			$settings['reservations_ipv4'] ?? $settings['reservations'] ?? array()
		),
	);
}

function wgclientexport_lock_path(string $tunnel, array $deps): string {
	if (isset($deps['lock_path'])) {
		return is_callable($deps['lock_path']) ? (string) ($deps['lock_path'])($tunnel) : (string) $deps['lock_path'];
	}
	global $g;
	$directory = is_array($g ?? null) && !empty($g['varrun_path']) ? $g['varrun_path'] : '/var/run';
	return $directory . '/wgclientexport-' . hash('sha256', $tunnel) . '.lock';
}

function wgclientexport_acquire_lock(string $path, float $timeout = 5.0) {
	$handle = @fopen($path, 'c');
	if ($handle === false) {
		return false;
	}
	$deadline = microtime(true) + max(0.1, min($timeout, 15.0));
	do {
		if (flock($handle, LOCK_EX | LOCK_NB)) {
			return $handle;
		}
		usleep(100000);
	} while (microtime(true) < $deadline);
	fclose($handle);
	return false;
}

function wgclientexport_sync_succeeded($response): bool {
	return is_array($response) && isset($response['ret_code']) && (int) $response['ret_code'] === 0;
}

function wgclientexport_rollback_peer(array $identity, string $tunnel, array $deps): bool {
	$delete = wgclientexport_dependency($deps, 'delete_peer', 'wgclientexport_wireguard_delete_peer');
	$sync = wgclientexport_dependency($deps, 'sync_tunnel', 'wgclientexport_wireguard_sync_tunnel');
	$confirm_absent = wgclientexport_dependency($deps, 'confirm_peer_absent',
		'wgclientexport_wireguard_confirm_peer_absent');
	try {
		$deleted = $delete($identity);
		$delete_ok = is_array($deleted)
			&& empty($deleted['input_errors'])
			&& (!empty($deleted['changes']) || !empty($deleted['persistent_absent']));
		return $delete_ok && wgclientexport_sync_succeeded($sync($tunnel))
			&& $confirm_absent($identity);
	} catch (Throwable $exception) {
		return false;
	}
}

function wgclientexport_tunnel_matches_pool(array $tunnel, string $pool): bool {
	$parsed_pool = wgclientexport_parse_ipv4_cidr($pool);
	if ($parsed_pool === null) {
		return false;
	}
	$rows = $tunnel['addresses']['row'] ?? $tunnel['addresses'] ?? array();
	if (is_array($rows) && isset($rows['address'])) {
		$rows = array($rows);
	}
	foreach ((array) $rows as $row) {
		$network = wgclientexport_cidr_from_mixed($row);
		$parsed_network = $network === null ? null : wgclientexport_parse_ipv4_cidr($network);
		if ($parsed_network !== null
		    && $parsed_pool['network_int'] >= $parsed_network['network_int']
		    && $parsed_pool['broadcast_int'] <= $parsed_network['broadcast_int']) {
			return true;
		}
	}
	return false;
}

function wgclientexport_provision(array $request, array $deps = array()): array {
	$raw_tunnel_name = (string) ($request['tunnel'] ?? $request['tun'] ?? '');
	$tunnel_name = trim($raw_tunnel_name);
	if (wgclientexport_has_line_break($raw_tunnel_name) || !preg_match('/^tun_wg\d+$/D', $tunnel_name)) {
		return wgclientexport_failure('validation_failed', wgclientexport_text('Select a valid WireGuard tunnel.'));
	}
	$initial_settings = wgclientexport_provision_settings($tunnel_name, $deps);
	if (!is_array($initial_settings) || ($initial_settings['enabled'] ?? 'no') !== 'yes') {
		return wgclientexport_failure('settings_unavailable',
			wgclientexport_text('Configure and enable Client Export for the selected tunnel first.'));
	}
	$intent = wgclientexport_merge_provision_request($request, $initial_settings);
	$errors = wgclientexport_validate_client_request($intent);
	if (!empty($errors)) {
		$result = wgclientexport_failure('validation_failed', $errors[0]);
		$result['input_errors'] = $errors;
		return $result;
	}
	$intent['client_name'] = trim($intent['client_name']);
	$intent['client_address'] = trim($intent['client_address']);
	try {
		$filename = wgclientexport_config_filename($intent['client_name']);
	} catch (InvalidArgumentException $exception) {
		return wgclientexport_failure('validation_failed',
			wgclientexport_text('Choose a client name that can be used as a safe configuration filename.'));
	}

	$lock = wgclientexport_acquire_lock(wgclientexport_lock_path($tunnel_name, $deps),
		(float) ($deps['lock_timeout'] ?? 5.0));
	if ($lock === false) {
		return wgclientexport_failure('busy',
			wgclientexport_text('Another client is being generated for this tunnel. Try again shortly.'));
	}

	$private_key = $configuration = null;
	$identity = null;
	try {
		$load = wgclientexport_dependency($deps, 'load', 'wgclientexport_wireguard_load');
		$readiness = $load();
		if ($readiness !== true && (!is_array($readiness) || empty($readiness['ready']))) {
			return wgclientexport_failure('wireguard_unavailable',
				wgclientexport_text('WireGuard is unavailable or its installed API contract is unsupported.'));
		}

		$settings = wgclientexport_provision_settings($tunnel_name, $deps);
		if (!is_array($settings) || ($settings['enabled'] ?? 'no') !== 'yes') {
			return wgclientexport_failure('settings_changed',
				wgclientexport_text('Client Export settings changed. Review them and try again.'));
		}
		$intent = wgclientexport_merge_provision_request($request, $settings);
		$errors = wgclientexport_validate_client_request($intent);
		if (!empty($errors)) {
			$result = wgclientexport_failure('validation_failed', $errors[0]);
			$result['input_errors'] = $errors;
			return $result;
		}
		$intent['client_name'] = trim($intent['client_name']);
		$intent['client_address'] = trim($intent['client_address']);

		$get_tunnel = wgclientexport_dependency($deps, 'get_tunnel', 'wgclientexport_wireguard_get_tunnel');
		$get_peers = wgclientexport_dependency($deps, 'get_peers', 'wgclientexport_wireguard_get_peers');
		$tunnel = $get_tunnel($tunnel_name);
		if (!is_array($tunnel) || empty($tunnel['enabled'])
		    || !wgclientexport_valid_wireguard_key((string) ($tunnel['public_key'] ?? ''))) {
			return wgclientexport_failure('tunnel_not_ready',
				wgclientexport_text('The selected WireGuard tunnel is missing, disabled, or has no valid public key.'));
		}
		if (!wgclientexport_tunnel_matches_pool($tunnel, $intent['pool'])) {
			return wgclientexport_failure('pool_mismatch',
				wgclientexport_text('The client pool must be contained within an IPv4 network configured on the selected tunnel.'));
		}

		$peers = $get_peers($tunnel_name);
		if (!is_array($peers)) {
			return wgclientexport_failure('peer_state_invalid',
				wgclientexport_text('The current WireGuard peer state could not be read safely.'));
		}
		foreach ($peers as $peer) {
			if (strcasecmp((string) ($peer['descr'] ?? ''), $intent['client_name']) === 0) {
				return wgclientexport_failure('duplicate_name',
					wgclientexport_text('A peer with this client name already exists on the selected tunnel.'));
			}
		}

		$used = wgclientexport_peer_allowed_ips($peers);
		$reserved = array_merge($intent['reservations_ipv4'], wgclientexport_tunnel_addresses($tunnel));
		$address = $intent['client_address'];
		if ($address === '') {
			try {
				$address = wgclientexport_allocate_ipv4($intent['pool'], $used, $reserved);
			} catch (RuntimeException $exception) {
				return wgclientexport_failure('pool_exhausted',
					wgclientexport_text('The configured client pool has no available IPv4 address.'));
			}
		} elseif (!wgclientexport_address_is_available($address, $intent['pool'], $used, $reserved)) {
			return wgclientexport_failure('address_unavailable',
				wgclientexport_text('The requested client address is outside the pool, reserved, or already allocated.'));
		}

		$allowed_ips = wgclientexport_build_allowed_ips(
			$intent['routing_profile'], $intent['local_routes_ipv4'], $intent['custom_routes_ipv4']
		);
		$keypair = wgclientexport_dependency($deps, 'keypair', 'wgclientexport_wireguard_generate_keypair');
		$keys = $keypair();
		if (!is_array($keys)) {
			return wgclientexport_failure('key_generation_failed',
				wgclientexport_text('WireGuard could not generate a valid client keypair.'));
		}
		$private_key = (string) ($keys['private_key'] ?? $keys['privkey'] ?? '');
		$public_key = (string) ($keys['public_key'] ?? $keys['pubkey'] ?? '');
		if (!wgclientexport_valid_wireguard_key($private_key) || !wgclientexport_valid_wireguard_key($public_key)) {
			return wgclientexport_failure('key_generation_failed',
				wgclientexport_text('WireGuard could not generate a valid client keypair.'));
		}

		$configuration = wgclientexport_render_client_config(array(
			'private_key' => $private_key,
			'address' => $address,
			'dns_ipv4' => $intent['dns_ipv4'],
			'server_public_key' => $tunnel['public_key'],
			'allowed_ips' => $allowed_ips,
			'endpoint_host' => $intent['endpoint_host'],
			'endpoint_port' => $intent['endpoint_port'],
			'persistent_keepalive' => $intent['persistent_keepalive'],
		));
		$current_peers = $get_peers($tunnel_name);
		if (!is_array($current_peers)) {
			return wgclientexport_failure('peer_state_invalid',
				wgclientexport_text('The current WireGuard peer state could not be revalidated safely.'));
		}
		foreach ($current_peers as $peer) {
			if (strcasecmp((string) ($peer['descr'] ?? ''), $intent['client_name']) === 0) {
				return wgclientexport_failure('concurrent_conflict',
					wgclientexport_text('Peer state changed during generation. Review the peer list and try again.'));
			}
		}
		if (!wgclientexport_address_is_available($address, $intent['pool'],
		    wgclientexport_peer_allowed_ips($current_peers), $reserved)) {
			return wgclientexport_failure('concurrent_conflict',
				wgclientexport_text('The selected address became unavailable. Review the peer list and try again.'));
		}

		$create = wgclientexport_dependency($deps, 'create_peer', 'wgclientexport_wireguard_create_peer');
		$created = $create(array('tunnel' => $tunnel_name, 'client_name' => $intent['client_name'],
			'public_key' => $public_key, 'address' => $address));
		$identity = is_array($created) ? ($created['identity'] ?? null) : null;
		if (!is_array($created) || !empty($created['input_errors']) || empty($created['changes']) || !is_array($identity)) {
			$rollback = is_array($identity) ? wgclientexport_rollback_peer($identity, $tunnel_name, $deps)
				: (!empty($created['changes']) ? false : null);
			return wgclientexport_failure($rollback === false ? 'rollback_failed' : 'peer_create_failed',
				$rollback === false
					? wgclientexport_text('Peer creation failed and rollback could not be confirmed. Inspect WireGuard peers now.')
					: wgclientexport_text('The WireGuard peer could not be created.'), $rollback);
		}

		$sync = wgclientexport_dependency($deps, 'sync_tunnel', 'wgclientexport_wireguard_sync_tunnel');
		$confirm = wgclientexport_dependency($deps, 'confirm_peer', 'wgclientexport_wireguard_confirm_peer');
		if (!wgclientexport_sync_succeeded($sync($tunnel_name)) || !$confirm($identity, $address)) {
			$rollback = wgclientexport_rollback_peer($identity, $tunnel_name, $deps);
			return wgclientexport_failure($rollback ? 'apply_failed' : 'rollback_failed',
				$rollback
					? wgclientexport_text('WireGuard apply failed. The new peer was rolled back.')
					: wgclientexport_text('WireGuard apply failed and rollback could not be confirmed. Inspect WireGuard peers now.'),
				$rollback);
		}

		return array(
			'input_errors' => array(), 'error_code' => null, 'changes' => true, 'rollback' => null,
			'result' => array('client_name' => $intent['client_name'], 'tunnel' => $tunnel_name,
				'address' => $address . '/32', 'public_key' => $public_key,
				'filename' => $filename,
				'configuration' => $configuration),
		);
	} catch (Throwable $exception) {
		$rollback = is_array($identity) ? wgclientexport_rollback_peer($identity, $tunnel_name, $deps) : null;
		return wgclientexport_failure($rollback === false ? 'rollback_failed' : 'internal_error',
			$rollback === false
				? wgclientexport_text('Client generation failed and rollback could not be confirmed. Inspect WireGuard peers now.')
				: wgclientexport_text('Client generation failed unexpectedly. No client credential was retained.'), $rollback);
	} finally {
		$private_key = null;
		$configuration = null;
		if (is_resource($lock)) {
			flock($lock, LOCK_UN);
			fclose($lock);
		}
	}
}
