<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

define('WGCLIENTEXPORT_MAX_ROUTES', 256);
wgce_require_modules([
    'files/usr/local/pkg/wgclientexport/validation.inc',
    'files/usr/local/pkg/wgclientexport/client_config.inc',
    'files/usr/local/pkg/wgclientexport/wireguard_adapter.inc',
]);

function wgce_read_project_asset(string $relativePath): string
{
    $contents = file_get_contents(wgce_project_root() . '/' . ltrim($relativePath, '/'));
    if ($contents === false) {
        throw new WgceTestFailure('Could not read project asset: ' . $relativePath);
    }
    return $contents;
}

function wgce_assert_source_declares_unique_id(string $source, string $id): void
{
    $quoted = preg_quote($id, '/');
    $patterns = [
        '/\bid\s*=\s*["\']' . $quoted . '["\']/',
        '/["\']id["\']\s*=>\s*["\']' . $quoted . '["\']/',
        '/setAttribute\s*\(\s*["\']id["\']\s*,\s*["\']' . $quoted . '["\']\s*\)/',
        '/new\s+Form_(?:Input|Button)\s*\(\s*["\']' . $quoted . '["\']/',
    ];
    $declarations = 0;
    foreach ($patterns as $pattern) {
        $count = preg_match_all($pattern, $source);
        if ($count === false) {
            throw new WgceTestFailure('Could not inspect source declarations for ID: ' . $id);
        }
        $declarations += $count;
    }
    wgce_assert_same(1, $declarations, 'Expected exactly one declaration for ID ' . $id);
}

wgce_test('current WireGuard exposes the supported mutation contract', static function (): void {
    $source = wgce_contract_source('WGCLIENTEXPORT_WG_CURRENT_SOURCE_DIR', 'wireguard-current');

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

wgce_test('current WireGuard preserves dynamic roaming peer semantics', static function (): void {
    $source = wgce_contract_source('WGCLIENTEXPORT_WG_CURRENT_SOURCE_DIR', 'wireguard-current');

    wgce_assert_matches(
        '/isset\s*\(\s*\$post\s*\[\s*[\'\"]dynamic[\'\"]\s*\]\s*\).*?' .
        'unset\s*\(\s*\$pconfig\s*\[\s*[\'\"]endpoint[\'\"]\s*\]\s*,\s*' .
        '\$pconfig\s*\[\s*[\'\"]port[\'\"]\s*\]\s*\)/s',
        $source,
        'The official dynamic peer path must remove firewall-side endpoint and port values'
    );
});

wgce_test('current WireGuard returns the peer mutation result shape used by the adapter', static function (): void {
    $source = wgce_contract_source('WGCLIENTEXPORT_WG_CURRENT_SOURCE_DIR', 'wireguard-current');

    foreach (['input_errors', 'changes', 'tuns_to_sync', 'pconfig'] as $key) {
        wgce_assert_matches(
            '/[\'\"]' . preg_quote($key, '/') . '[\'\"]\s*=>/',
            $source,
            'Missing wg_do_peer_post result key: ' . $key
        );
    }
});

wgce_test('renderer rejects a configuration whose canonical bytes exceed 2048', static function (): void {
    wgce_assert_same(2048, WGCLIENTEXPORT_MAX_CONFIG_BYTES);
    $routes = [];
    for ($index = 0; $index < 128; ++$index) {
        $routes[] = '10.50.0.' . $index . '/32';
    }

    wgce_assert_throws(
        static fn(): string => wgclientexport_render_client_config([
            'private_key' => wgce_synthetic_key('C'),
            'address' => '10.77.0.2/32',
            'dns_ipv4' => ['192.0.2.53'],
            'server_public_key' => wgce_synthetic_key('S'),
            'allowed_ips' => $routes,
            'endpoint_host' => 'vpn.example.test',
            'endpoint_port' => '51820',
            'persistent_keepalive' => '25',
        ]),
        InvalidArgumentException::class
    );
});

wgce_test('result UI installs copy and download handlers before QR construction', static function (): void {
    $page = wgce_read_project_asset('files/usr/local/www/wgclientexport/vpn_wg_client_export.php');
    $copyHandler = strpos($page, "getElementById('wgce-copy').addEventListener");
    $downloadHandler = strpos($page, "getElementById('wgce-download').addEventListener");
    $qrConstruction = strpos($page, 'new QRCode(');

    wgce_assert_true($copyHandler !== false, 'Copy handler is missing');
    wgce_assert_true($downloadHandler !== false, 'Download handler is missing');
    wgce_assert_true($qrConstruction !== false, 'QR construction is missing');
    wgce_assert_true($copyHandler < $qrConstruction, 'Copy handler must be installed before QR construction');
    wgce_assert_true($downloadHandler < $qrConstruction, 'Download handler must be installed before QR construction');
});

wgce_test('QR construction has a visible try-catch fallback', static function (): void {
    $page = wgce_read_project_asset('files/usr/local/www/wgclientexport/vpn_wg_client_export.php');
    $qrConstruction = strpos($page, 'new QRCode(');
    wgce_assert_true($qrConstruction !== false, 'QR construction is missing');
    $tryBlock = strrpos(substr($page, 0, $qrConstruction), 'try {');
    $catchBlock = strpos($page, '} catch (error)', $qrConstruction);
    $fallback = strpos($page, "getElementById('wgce-qrcode').textContent", $qrConstruction);

    wgce_assert_true($tryBlock !== false, 'QR construction is not guarded by try');
    wgce_assert_true($catchBlock !== false, 'QR construction has no catch fallback');
    wgce_assert_true($fallback !== false, 'QR failure does not render fallback text');
    wgce_assert_true($tryBlock < $qrConstruction && $qrConstruction < $catchBlock);
    wgce_assert_true($catchBlock < $fallback, 'QR fallback must execute inside the catch path');
});

wgce_test('result action status is announced through an aria-live region', static function (): void {
    $page = wgce_read_project_asset('files/usr/local/www/wgclientexport/vpn_wg_client_export.php');
    wgce_assert_matches(
        '/<[^>]+id=["\']wgce-action-status["\'][^>]+(?:role=["\']status["\'][^>]+aria-live=["\']polite["\']' .
        '|aria-live=["\']polite["\'][^>]+role=["\']status["\'])[^>]*>/',
        $page,
        'Result status must be a polite live status region'
    );
});

wgce_test('settings suggestions and missing endpoint have explicit UI messages', static function (): void {
    $page = wgce_read_project_asset('files/usr/local/www/wgclientexport/vpn_wg_client_export.php');

    wgce_assert_contains(
        'Suggested values were detected from pfSense. Review the public endpoint, then save the settings.',
        $page,
        'The page must explain that unsaved values are suggestions'
    );
    wgce_assert_contains(
        'A public endpoint could not be detected. Enter a public hostname or IPv4 address.',
        $page,
        'The page must explain when endpoint detection produced no value'
    );
    $suggestionGuard = strpos($page, 'if ($suggestions_applied) {');
    $suggestionMessage = strpos($page, 'Suggested values were detected from pfSense.');
    $endpointGuard = strpos(
        $page,
        "if (trim((string) (\$settings_values['endpoint_host'] ?? '')) === '') {"
    );
    $endpointMessage = strpos($page, 'A public endpoint could not be detected.');
    wgce_assert_true($suggestionGuard !== false, 'Suggested values must have a render guard');
    wgce_assert_true($endpointGuard !== false, 'Missing endpoint must have an empty-value guard');
    wgce_assert_true(
        $suggestionGuard < $suggestionMessage
        && $suggestionMessage < $endpointGuard
        && $endpointGuard < $endpointMessage,
        'Suggestion notices must remain inside their ordered conditional rendering block'
    );
});

wgce_test('settings and client forms declare distinct IDs for forms, actions, fields, and buttons', static function (): void {
    $page = wgce_read_project_asset('files/usr/local/www/wgclientexport/vpn_wg_client_export.php');
    $ids = [
        'wgce_settings_form',
        'wgce_client_form',
        'wgce_settings_action',
        'wgce_provision_action',
        'wgce_client_dns_ipv4',
        'wgce_client_persistent_keepalive',
        'wgce_save_settings',
        'wgce_generate_client',
    ];

    wgce_assert_same(count($ids), count(array_unique($ids)), 'Contract IDs must be distinct');
    foreach ($ids as $id) {
        wgce_assert_source_declares_unique_id($page, $id);
    }
});

wgce_test('client name has an accessible label and gates the Generate button', static function (): void {
    $page = wgce_read_project_asset('files/usr/local/www/wgclientexport/vpn_wg_client_export.php');
    $matched = preg_match(
        '/new\s+Form_Input\s*\(\s*["\']client_name["\']/',
        $page,
        $clientInputMatch,
        PREG_OFFSET_CAPTURE
    );
    wgce_assert_same(1, $matched, 'Client name input is missing');
    $clientInputSource = substr($page, $clientInputMatch[0][1], 700);
    wgce_assert_matches(
        '/["\']aria-label["\']\s*=>\s*gettext\s*\(\s*["\']Client name["\']\s*\)/',
        $clientInputSource,
        'Client name input must expose an aria-label'
    );

    wgce_assert_contains("$('#client_name')", $page, 'Client name field must be observed by JavaScript');
    wgce_assert_contains(
        "$('#wgce_generate_client')",
        $page,
        'Generate button must be controlled by JavaScript'
    );
    wgce_assert_matches(
        '/\.prop\s*\(\s*["\']disabled["\']\s*,/',
        $page,
        'Generate button must use its disabled property'
    );
    wgce_assert_matches(
        '/#client_name["\']\)\.on\s*\(\s*["\'][^"\']*input/',
        $page,
        'Generate state must update when the client name changes'
    );
    wgce_assert_matches(
        '/(?:\.trim\s*\(\s*\)|\$\.trim\s*\()/',
        $page,
        'Whitespace-only client names must be treated as empty'
    );
});

wgce_test('page uses suggestion wrapper and stored settings bypass suggestion generation', static function (): void {
    $page = wgce_read_project_asset('files/usr/local/www/wgclientexport/vpn_wg_client_export.php');
    $config = wgce_read_project_asset('files/usr/local/pkg/wgclientexport/config.inc');

    wgce_assert_same(
        1,
        preg_match_all('/wgclientexport_settings_for_ui\s*\(/', $page),
        'The page must resolve its initial values through the UI settings wrapper exactly once'
    );
    wgce_assert_same(
        0,
        preg_match_all('/wgclientexport_suggest_tunnel_settings\s*\(/', $page),
        'The page must not call the low-level suggestion helper directly'
    );
    wgce_assert_matches(
        '/wgclientexport_settings_for_ui\s*\([\s\S]{0,800}\$stored\s*\)/',
        $page,
        'Stored settings must be passed to the UI settings wrapper'
    );
    wgce_assert_matches(
        '/\$suggestions_applied\s*=\s*!is_array\s*\(\s*\$stored\s*\)\s*;/',
        $page,
        'Suggestion mode must be derived exclusively from absence of stored settings'
    );
    wgce_assert_matches(
        '/\$suggestion_context\s*=\s*\$suggestions_applied\s*\?\s*' .
        'wgclientexport_page_suggestion_context\s*\(\s*\)\s*:\s*array\s*\(\s*\)\s*;/',
        $page,
        'pfSense suggestion context must only be collected without stored settings'
    );
    wgce_assert_matches(
        '/function\s+wgclientexport_settings_for_ui\s*\([\s\S]{0,300}' .
        '\?array\s+\$stored\s*=\s*null[\s\S]{0,100}\)\s*:\s*array\s*\{' .
        '[\s\S]{0,500}\$stored\s*===\s*null\s*\?' .
        '[\s\S]{0,300}wgclientexport_suggest_tunnel_settings\s*\(' .
        '[\s\S]{0,300}:\s*wgclientexport_sanitize_tunnel_setting\s*\(\s*\$stored\s*\)/',
        $config,
        'Suggestion generation must only occur when no stored row exists'
    );
});

wgce_test('routing defaults to full tunnel when no local routes are stored', static function (): void {
    $page = wgce_read_project_asset('files/usr/local/www/wgclientexport/vpn_wg_client_export.php');
    $assignment = strpos($page, '$default_routing_profile =');
    wgce_assert_true($assignment !== false, 'Default routing profile assignment is missing');
    $assignmentSource = substr($page, $assignment, 350);
    wgce_assert_contains("\$stored['local_routes_ipv4']", $assignmentSource);
    wgce_assert_matches(
        '/\?\s*["\']full["\']\s*:\s*["\']local["\']/',
        $assignmentSource,
        'An empty local route list must select the full-tunnel profile'
    );
});

wgce_test('vendored QR code never assigns payload text to a title', static function (): void {
    $source = wgce_read_project_asset('files/usr/local/www/wgclientexport/js/qrcode.js');
    wgce_assert_same(
        0,
        preg_match('/\.title\s*=|setAttribute(?:NS)?\s*\(\s*["\']title["\']/', $source),
        'QR implementation must not expose configuration text through a title attribute'
    );
});

wgce_test('missing assignment and runtime capabilities fail the adapter contract closed', static function (): void {
    foreach ([
        'wg_get_configured_ifs',
        'wg_tunnel_get_peers_running_keys',
        'is_wg_tunnel_assigned',
        'wg_get_pfsense_interface_info',
        'get_interface_ip',
        'get_interface_subnet',
    ] as $capability) {
        wgce_assert_true(
            in_array($capability, wgclientexport_wireguard_required_functions(), true),
            'Required capability is missing from adapter contract: ' . $capability
        );
    }

    if (!function_exists('wg_globals')) {
        function wg_globals(): void
        {
            global $wgg;
            $wgg = ['tunnels' => [], 'peers' => []];
        }
        function wg_do_peer_post(array $post): array
        {
            return ['input_errors' => [], 'changes' => false];
        }
        function wg_tunnel_sync(
            array $tunnels,
            bool $restartServices = false,
            bool $resolveEndpoints = true,
            bool $json = false
        ): array {
            return ['ret_code' => 0, 'tunnels' => []];
        }
        function wg_delete_peer(int $index): array
        {
            return ['input_errors' => [], 'changes' => false];
        }
        function wg_get_configured_ifs(): array
        {
            return [];
        }
        function wg_tunnel_get_config_by_name(string $name): false
        {
            return false;
        }
        function wg_tunnel_get_peers_config(string $name): array
        {
            return [];
        }
        function wg_gen_keypair(bool $json = false): array
        {
            return [];
        }
        function wg_is_service_enabled(): bool
        {
            return true;
        }
        function wg_is_service_running(): bool
        {
            return true;
        }
    }

    $readiness = wgclientexport_wireguard_load(false);
    wgce_assert_false($readiness['ready']);
    wgce_assert_same(null, $readiness['contract']);
    wgce_assert_true($readiness['input_errors'] !== []);
});

wgce_test_run();
