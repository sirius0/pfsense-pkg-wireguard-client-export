<?php
/*
 * ip_allocator.inc
 *
 * Deterministic, side-effect-free IPv4 allocation.
 */

function wgclientexport_cidr_from_mixed($value): ?string {
	if (is_array($value)) {
		if (isset($value['address'], $value['mask'])) {
			$value = $value['address'] . '/' . $value['mask'];
		} elseif (isset($value['cidr'])) {
			$value = $value['cidr'];
		} else {
			return null;
		}
	}

	$value = trim((string) $value);
	if ($value === '') {
		return null;
	}
	if (!str_contains($value, '/')) {
		$value .= '/32';
	}
	return wgclientexport_normalize_ipv4_cidr($value);
}

function wgclientexport_ipv4_intervals(array $values): array {
	$intervals = array();
	foreach ($values as $value) {
		$cidr = wgclientexport_cidr_from_mixed($value);
		if ($cidr === null) {
			continue;
		}
		$parsed = wgclientexport_parse_ipv4_cidr($cidr);
		$intervals[] = array($parsed['network_int'], $parsed['broadcast_int']);
	}

	usort($intervals, static function (array $left, array $right): int {
		return $left[0] <=> $right[0];
	});

	$merged = array();
	foreach ($intervals as $interval) {
		$last = count($merged) - 1;
		if ($last < 0 || $interval[0] > $merged[$last][1] + 1) {
			$merged[] = $interval;
		} else {
			$merged[$last][1] = max($merged[$last][1], $interval[1]);
		}
	}
	return $merged;
}

function wgclientexport_allocate_ipv4(string $cidr, array $used = array(), array $reserved = array()): string {
	$pool = wgclientexport_parse_ipv4_cidr($cidr);
	if ($pool === null || $pool['prefix'] > 30) {
		throw new InvalidArgumentException(wgclientexport_text('The client pool must be an IPv4 CIDR with at least four addresses.'));
	}

	$blocked = wgclientexport_ipv4_intervals(array_merge($used, $reserved));
	$candidate = $pool['network_int'] + 1;
	$last_candidate = $pool['broadcast_int'] - 1;

	foreach ($blocked as [$start, $end]) {
		if ($end < $candidate) {
			continue;
		}
		if ($start > $last_candidate) {
			break;
		}
		if ($start > $candidate) {
			break;
		}
		$candidate = $end + 1;
		if ($candidate > $last_candidate) {
			break;
		}
	}

	if ($candidate > $last_candidate) {
		throw new RuntimeException(wgclientexport_text('The configured client pool has no available IPv4 address.'));
	}
	return wgclientexport_int_to_ipv4($candidate);
}

function wgclientexport_address_is_available(
	string $address,
	string $pool,
	array $used = array(),
	array $reserved = array()
): bool {
	$address_int = wgclientexport_ipv4_to_int($address);
	$parsed_pool = wgclientexport_parse_ipv4_cidr($pool);
	if ($address_int === null || $parsed_pool === null || $parsed_pool['prefix'] > 30
	    || $address_int <= $parsed_pool['network_int']
	    || $address_int >= $parsed_pool['broadcast_int']) {
		return false;
	}
	foreach (wgclientexport_ipv4_intervals(array_merge($used, $reserved)) as [$start, $end]) {
		if ($address_int >= $start && $address_int <= $end) {
			return false;
		}
	}
	return true;
}

function wgclientexport_peer_allowed_ips(array $peers): array {
	$used = array();
	foreach ($peers as $peer) {
		$rows = $peer['allowedips']['row'] ?? $peer['allowed_ips'] ?? array();
		foreach ((array) $rows as $row) {
			$cidr = wgclientexport_cidr_from_mixed($row);
			if ($cidr !== null) {
				$used[] = $cidr;
			}
		}
	}
	return array_values(array_unique($used));
}

function wgclientexport_tunnel_addresses(array $tunnel): array {
	$addresses = array();
	foreach ((array) ($tunnel['addresses']['row'] ?? $tunnel['addresses'] ?? array()) as $row) {
		$value = is_array($row) ? (string) ($row['address'] ?? '') : explode('/', (string) $row, 2)[0];
		$value = trim($value);
		if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$addresses[] = $value . '/32';
		}
	}
	return array_values(array_unique($addresses));
}

function wgclientexport_suggest_address(string $tunnel, string $pool): string {
	$tunnel_config = wgclientexport_wireguard_get_tunnel($tunnel);
	if ($tunnel_config === null) {
		throw new RuntimeException(wgclientexport_text('The selected WireGuard tunnel does not exist.'));
	}
	$peers = wgclientexport_wireguard_get_peers($tunnel);
	return wgclientexport_allocate_ipv4(
		$pool,
		wgclientexport_peer_allowed_ips($peers),
		wgclientexport_tunnel_addresses($tunnel_config)
	);
}
