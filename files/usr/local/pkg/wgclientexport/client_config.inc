<?php
/*
 * client_config.inc
 *
 * Canonical in-memory WireGuard client configuration rendering.
 */

function wgclientexport_client_config_endpoint(array $data): array {
	$raw_host = (string) ($data['endpoint_host'] ?? '');
	$host = trim($raw_host);
	$port = (string) ($data['endpoint_port'] ?? '');

	if ($host === '' && isset($data['endpoint'])) {
		$endpoint = (string) $data['endpoint'];
		if (wgclientexport_has_line_break($endpoint)) {
			throw new InvalidArgumentException(wgclientexport_text('The WireGuard endpoint is invalid.'));
		}
		$endpoint = trim($endpoint);
		if (preg_match('/^([^:]+):(\d{1,5})$/D', $endpoint, $matches)) {
			$host = $matches[1];
			$port = $matches[2];
		}
	}

	if (wgclientexport_has_line_break($raw_host) || !wgclientexport_valid_endpoint_host($host)
	    || !ctype_digit($port) || (int) $port < 1 || (int) $port > 65535) {
		throw new InvalidArgumentException(wgclientexport_text('The WireGuard endpoint is invalid.'));
	}
	return array($host, (int) $port);
}

function wgclientexport_render_client_config(array $data): string {
	$raw_private_key = (string) ($data['private_key'] ?? $data['privatekey'] ?? '');
	$raw_public_key = (string) ($data['server_public_key'] ?? $data['public_key'] ?? '');
	if (wgclientexport_has_line_break($raw_private_key) || wgclientexport_has_line_break($raw_public_key)) {
		throw new InvalidArgumentException(wgclientexport_text('A WireGuard key is invalid.'));
	}
	$private_key = trim($raw_private_key);
	$server_public_key = trim($raw_public_key);
	if (!wgclientexport_valid_wireguard_key($private_key)
	    || !wgclientexport_valid_wireguard_key($server_public_key)) {
		throw new InvalidArgumentException(wgclientexport_text('A WireGuard key is invalid.'));
	}

	$address = trim((string) ($data['address'] ?? ''));
	if (!str_contains($address, '/')) {
		$address .= '/32';
	}
	$parsed_address = wgclientexport_parse_ipv4_cidr($address);
	if ($parsed_address === null || $parsed_address['prefix'] !== 32) {
		throw new InvalidArgumentException(wgclientexport_text('The client address must be a valid IPv4 /32 address.'));
	}

	$allowed_ips = wgclientexport_normalize_ipv4_cidrs(
		wgclientexport_normalize_list($data['allowed_ips'] ?? array())
	);
	if (empty($allowed_ips)) {
		throw new InvalidArgumentException(wgclientexport_text('At least one client AllowedIPs route is required.'));
	}
	if (count($allowed_ips) > WGCLIENTEXPORT_MAX_ROUTES) {
		throw new InvalidArgumentException(wgclientexport_text('A client configuration can contain at most 32 routes.'));
	}

	$dns = array();
	foreach (wgclientexport_normalize_list($data['dns_ipv4'] ?? $data['dns'] ?? array()) as $resolver) {
		$resolver = trim((string) $resolver);
		if (!filter_var($resolver, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			throw new InvalidArgumentException(wgclientexport_text('A DNS resolver is invalid.'));
		}
		if (!in_array($resolver, $dns, true)) {
			$dns[] = $resolver;
		}
	}
	if (count($dns) > WGCLIENTEXPORT_MAX_DNS_SERVERS) {
		throw new InvalidArgumentException(wgclientexport_text('A client configuration can contain at most four DNS resolvers.'));
	}

	$keepalive = (string) ($data['persistent_keepalive'] ?? $data['persistentkeepalive'] ?? '0');
	if ($keepalive === '') {
		$keepalive = '0';
	}
	if (!ctype_digit($keepalive) || (int) $keepalive > 65535) {
		throw new InvalidArgumentException(wgclientexport_text('Persistent keepalive is invalid.'));
	}
	[$endpoint_host, $endpoint_port] = wgclientexport_client_config_endpoint($data);

	$lines = array(
		'[Interface]',
		"PrivateKey = {$private_key}",
		'Address = ' . $parsed_address['address'] . '/32',
	);
	if (!empty($dns)) {
		$lines[] = 'DNS = ' . implode(', ', $dns);
	}
	$lines[] = '';
	$lines[] = '[Peer]';
	$lines[] = "PublicKey = {$server_public_key}";
	$lines[] = 'AllowedIPs = ' . implode(', ', $allowed_ips);
	$lines[] = "Endpoint = {$endpoint_host}:{$endpoint_port}";
	if ((int) $keepalive > 0) {
		$lines[] = 'PersistentKeepalive = ' . (int) $keepalive;
	}

	$configuration = implode("\n", $lines) . "\n";
	if (strlen($configuration) > WGCLIENTEXPORT_MAX_CONFIG_BYTES) {
		throw new InvalidArgumentException(wgclientexport_text('The client configuration is too large for one-time QR delivery.'));
	}
	return $configuration;
}

function wgclientexport_config_filename(string $client_name): string {
	if ($client_name === '' || wgclientexport_has_line_break($client_name)
	    || preg_match('/[\x00-\x1f\x7f]/', $client_name)
	    || strpbrk($client_name, "/\\") !== false
	    || str_contains($client_name, '..')) {
		throw new InvalidArgumentException(wgclientexport_text('The client name cannot be used as a safe filename.'));
	}
	$basename = preg_replace('/[^A-Za-z0-9._-]+/', '-', trim($client_name));
	$basename = trim((string) $basename, '.-_');
	$basename = substr($basename, 0, 64);
	if ($basename === '') {
		throw new InvalidArgumentException(wgclientexport_text('The client name cannot be used as a safe filename.'));
	}
	return $basename . '.conf';
}
