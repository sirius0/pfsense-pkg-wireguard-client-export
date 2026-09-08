<?php
/*
 * validation.inc
 *
 * Pure input validation helpers for WireGuard Client Export.
 */

if (!defined('WGCLIENTEXPORT_MAX_ROUTES')) {
	define('WGCLIENTEXPORT_MAX_ROUTES', 32);
}
if (!defined('WGCLIENTEXPORT_MAX_DNS_SERVERS')) {
	define('WGCLIENTEXPORT_MAX_DNS_SERVERS', 4);
}
if (!defined('WGCLIENTEXPORT_MAX_CONFIG_BYTES')) {
	define('WGCLIENTEXPORT_MAX_CONFIG_BYTES', 2048);
}

function wgclientexport_text(string $message): string {
	return function_exists('gettext') ? gettext($message) : $message;
}

function wgclientexport_has_line_break(string $value): bool {
	return str_contains($value, "\r") || str_contains($value, "\n");
}

function wgclientexport_ipv4_to_int(string $address): ?int {
	$packed = @inet_pton($address);
	if ($packed === false || strlen($packed) !== 4) {
		return null;
	}

	return (int) unpack('Naddress', $packed)['address'];
}

function wgclientexport_int_to_ipv4(int $address): string {
	return inet_ntop(pack('N', $address & 0xffffffff));
}

function wgclientexport_parse_ipv4_cidr(string $cidr): ?array {
	if (wgclientexport_has_line_break($cidr)) {
		return null;
	}
	$cidr = trim($cidr);
	if (!preg_match('/^([^\/]+)\/(\d{1,2})$/D', $cidr, $matches)) {
		return null;
	}

	$address = wgclientexport_ipv4_to_int($matches[1]);
	$prefix = (int) $matches[2];
	if ($address === null || $prefix < 0 || $prefix > 32) {
		return null;
	}

	$mask = $prefix === 0 ? 0 : ((0xffffffff << (32 - $prefix)) & 0xffffffff);
	$network = $address & $mask;
	$broadcast = $network | ((~$mask) & 0xffffffff);

	return array(
		'address' => wgclientexport_int_to_ipv4($address),
		'address_int' => $address,
		'prefix' => $prefix,
		'network' => wgclientexport_int_to_ipv4($network),
		'network_int' => $network,
		'broadcast' => wgclientexport_int_to_ipv4($broadcast),
		'broadcast_int' => $broadcast,
		'cidr' => wgclientexport_int_to_ipv4($network) . "/{$prefix}",
	);
}

function wgclientexport_normalize_ipv4_cidr(string $cidr): ?string {
	$parsed = wgclientexport_parse_ipv4_cidr($cidr);
	return $parsed === null ? null : $parsed['cidr'];
}

function wgclientexport_ipv4_in_cidr(string $address, string $cidr): bool {
	$address_int = wgclientexport_ipv4_to_int(trim($address));
	$parsed = wgclientexport_parse_ipv4_cidr($cidr);

	return $address_int !== null && $parsed !== null
		&& $address_int >= $parsed['network_int']
		&& $address_int <= $parsed['broadcast_int'];
}

function wgclientexport_normalize_list($value): array {
	if (is_string($value)) {
		$value = preg_split('/[\s,]+/', trim($value), -1, PREG_SPLIT_NO_EMPTY);
	} elseif (is_array($value) && array_key_exists('item', $value)) {
		$value = is_array($value['item']) ? $value['item'] : array($value['item']);
	}
	return is_array($value) ? array_values($value) : array();
}

function wgclientexport_normalize_ipv4_cidrs(array $values): array {
	$result = array();
	foreach ($values as $value) {
		$cidr = wgclientexport_normalize_ipv4_cidr((string) $value);
		if ($cidr === null) {
			throw new InvalidArgumentException(wgclientexport_text('An IPv4 route is invalid.'));
		}
		if (!in_array($cidr, $result, true)) {
			$result[] = $cidr;
		}
	}
	return $result;
}

function wgclientexport_build_allowed_ips(string $mode, array $local = array(), array $custom = array()): array {
	switch ($mode) {
		case 'full':
			return array('0.0.0.0/0');
		case 'local':
			$routes = wgclientexport_normalize_ipv4_cidrs($local);
			break;
		case 'custom':
			$routes = wgclientexport_normalize_ipv4_cidrs($custom);
			break;
		default:
			throw new InvalidArgumentException(wgclientexport_text('The routing profile is invalid.'));
	}

	if (empty($routes)) {
		throw new InvalidArgumentException(wgclientexport_text('At least one IPv4 route is required.'));
	}
	if (count($routes) > WGCLIENTEXPORT_MAX_ROUTES) {
		throw new InvalidArgumentException(wgclientexport_text('A client configuration can contain at most 32 routes.'));
	}
	return $routes;
}

function wgclientexport_valid_endpoint_host(string $host): bool {
	if ($host === '' || wgclientexport_has_line_break($host)
	    || filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
		return false;
	}
	if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
		return true;
	}
	return strlen($host) <= 253
		&& (bool) preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/Di', $host);
}

function wgclientexport_valid_wireguard_key(string $key): bool {
	return !wgclientexport_has_line_break($key)
		&& (bool) preg_match('/^[A-Za-z0-9+\/]{43}=$/D', $key);
}

function wgclientexport_validate_client_request(array $data): array {
	$errors = array();
	$raw_tunnel = (string) ($data['tunnel'] ?? $data['tun'] ?? '');
	$raw_name = (string) ($data['client_name'] ?? $data['name'] ?? $data['descr'] ?? '');
	$raw_pool = (string) ($data['pool'] ?? $data['client_pool_ipv4'] ?? '');
	$raw_host = (string) ($data['endpoint_host'] ?? '');
	$tunnel = trim($raw_tunnel);
	$name = trim($raw_name);
	$pool = trim($raw_pool);
	$host = trim($raw_host);
	$port = (string) ($data['endpoint_port'] ?? '');
	$mode = (string) ($data['routing_profile'] ?? $data['access_mode'] ?? '');
	$raw_client_address = (string) ($data['client_address'] ?? $data['address'] ?? '');

	if (wgclientexport_has_line_break($raw_tunnel) || !preg_match('/^tun_wg\d+$/D', $tunnel)) {
		$errors[] = wgclientexport_text('Select a valid WireGuard tunnel.');
	}
	if ($name === '' || strlen($name) > 64 || wgclientexport_has_line_break($raw_name)
	    || preg_match('/[\x00-\x1f\x7f]/', $name)) {
		$errors[] = wgclientexport_text('The client name must contain 1 to 64 printable characters.');
	}
	$parsed_pool = wgclientexport_parse_ipv4_cidr($pool);
	if ($parsed_pool === null || $parsed_pool['prefix'] > 30) {
		$errors[] = wgclientexport_text('The client pool must be a valid IPv4 network with at least four addresses.');
	}
	if (wgclientexport_has_line_break($raw_host) || !wgclientexport_valid_endpoint_host($host)) {
		$errors[] = wgclientexport_text('The endpoint must be a valid hostname or IPv4 address.');
	}
	if (!ctype_digit($port) || (int) $port < 1 || (int) $port > 65535) {
		$errors[] = wgclientexport_text('The endpoint port must be between 1 and 65535.');
	}
	if (!in_array($mode, array('local', 'full', 'custom'), true)) {
		$errors[] = wgclientexport_text('Select a valid routing profile.');
	} else {
		try {
			wgclientexport_build_allowed_ips(
				$mode,
				wgclientexport_normalize_list($data['local_routes_ipv4'] ?? $data['local_networks'] ?? array()),
				wgclientexport_normalize_list($data['custom_routes_ipv4'] ?? $data['custom_allowed_ips'] ?? array())
			);
		} catch (InvalidArgumentException $exception) {
			$errors[] = $exception->getMessage();
		}
	}

	$keepalive = (string) ($data['persistent_keepalive'] ?? $data['persistentkeepalive'] ?? '0');
	if ($keepalive === '' || !ctype_digit($keepalive) || (int) $keepalive > 65535) {
		$errors[] = wgclientexport_text('Persistent keepalive must be between 0 and 65535.');
	}
	$dns_values = wgclientexport_normalize_list($data['dns_ipv4'] ?? $data['dns'] ?? array());
	if (count($dns_values) > WGCLIENTEXPORT_MAX_DNS_SERVERS) {
		$errors[] = wgclientexport_text('A client configuration can contain at most four DNS resolvers.');
	}
	foreach ($dns_values as $dns) {
		if (!filter_var((string) $dns, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$errors[] = wgclientexport_text('Every DNS resolver must be a valid IPv4 address.');
			break;
		}
	}
	if ($raw_client_address !== ''
	    && (wgclientexport_has_line_break($raw_client_address)
	    || !filter_var(trim($raw_client_address), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))) {
		$errors[] = wgclientexport_text('The requested client address must be a valid IPv4 address.');
	}

	return array_values(array_unique($errors));
}

function wgclientexport_find_duplicate_allowed_ip(array $candidate, array $peers, ?string $tunnel = null): ?string {
	foreach ($candidate as $value) {
		$needle = wgclientexport_normalize_ipv4_cidr((string) $value);
		if ($needle === null) {
			continue;
		}
		foreach ($peers as $peer) {
			if ($tunnel !== null && ($peer['tun'] ?? null) !== $tunnel) {
				continue;
			}
			$rows = $peer['allowedips']['row'] ?? $peer['allowed_ips'] ?? array();
			foreach ((array) $rows as $row) {
				$existing = is_array($row)
					? (($row['address'] ?? '') . '/' . ($row['mask'] ?? ''))
					: (string) $row;
				if (wgclientexport_normalize_ipv4_cidr($existing) === $needle) {
					return $needle;
				}
			}
		}
	}
	return null;
}
