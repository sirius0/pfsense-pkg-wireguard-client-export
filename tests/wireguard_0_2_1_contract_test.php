<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

wgce_test('WireGuard 0.2.1 exposes the supported mutation contract', static function (): void {
    $source = wgce_contract_source('WGCLIENTEXPORT_WG_0_2_1_SOURCE_DIR', 'wireguard-0.2.1');

    wgce_assert_function_signature($source, 'wg_globals', []);
    wgce_assert_function_signature($source, 'wg_do_peer_post', ['$post']);
    wgce_assert_function_signature($source, 'wg_delete_peer', ['$peer_idx']);
    wgce_assert_function_signature($source, 'wg_tunnel_sync', [
        '$tunnel_names',
        '$restart_services = false',
        '$resolve_endpoints = true',
        '$json = false',
    ]);
    wgce_assert_function_signature($source, 'wg_get_configured_ifs', []);
    wgce_assert_function_signature($source, 'wg_tunnel_get_config_by_name', ['$tunnel_name']);
    wgce_assert_function_signature($source, 'wg_tunnel_get_peers_config', ['$tunnel_name']);
    wgce_assert_function_signature($source, 'wg_tunnel_get_peers_running_keys', ['$tunnel_name']);
    wgce_assert_function_signature($source, 'wg_gen_keypair', ['$json = false']);
    wgce_assert_function_signature($source, 'wg_is_service_enabled', []);
    wgce_assert_function_signature($source, 'wg_is_service_running', []);
    wgce_assert_function_signature($source, 'is_wg_tunnel_assigned', ['$tunnel_name', '$disabled = true']);
    wgce_assert_function_signature($source, 'wg_get_pfsense_interface_info', ['$tunnel_name']);
});

wgce_test('WireGuard 0.2.1 preserves dynamic roaming peer semantics', static function (): void {
    $source = wgce_contract_source('WGCLIENTEXPORT_WG_0_2_1_SOURCE_DIR', 'wireguard-0.2.1');

    wgce_assert_matches(
        '/isset\s*\(\s*\$post\s*\[\s*[\'\"]dynamic[\'\"]\s*\]\s*\).*?' .
        'unset\s*\(\s*\$pconfig\s*\[\s*[\'\"]endpoint[\'\"]\s*\]\s*,\s*' .
        '\$pconfig\s*\[\s*[\'\"]port[\'\"]\s*\]\s*\)/s',
        $source,
        'The official dynamic peer path must remove firewall-side endpoint and port values'
    );
});

wgce_test('WireGuard 0.2.1 returns the peer mutation result shape used by the adapter', static function (): void {
    $source = wgce_contract_source('WGCLIENTEXPORT_WG_0_2_1_SOURCE_DIR', 'wireguard-0.2.1');

    foreach (['input_errors', 'changes', 'tuns_to_sync', 'pconfig'] as $key) {
        wgce_assert_matches(
            '/[\'\"]' . preg_quote($key, '/') . '[\'\"]\s*=>/',
            $source,
            'Missing wg_do_peer_post result key: ' . $key
        );
    }
});

wgce_test_run();
