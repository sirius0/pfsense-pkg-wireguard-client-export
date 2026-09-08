<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
wgce_require_modules([
    'files/usr/local/pkg/wgclientexport/validation.inc',
    'files/usr/local/pkg/wgclientexport/client_config.inc',
]);

function wgce_client_config_data(array $overrides = []): array
{
    return array_replace([
        'private_key' => wgce_synthetic_key('C'),
        'address' => '10.77.0.2',
        'dns_ipv4' => ['192.0.2.53', '198.51.100.53'],
        'server_public_key' => wgce_synthetic_key('S'),
        'allowed_ips' => ['192.0.2.0/24', '198.51.100.0/24'],
        'endpoint_host' => 'vpn.example.test',
        'endpoint_port' => '51820',
        'persistent_keepalive' => '25',
    ], $overrides);
}

wgce_test('renderer emits canonical WireGuard configuration bytes', static function (): void {
    $data = wgce_client_config_data();
    $expected = implode("\n", [
        '[Interface]',
        'PrivateKey = ' . $data['private_key'],
        'Address = 10.77.0.2/32',
        'DNS = 192.0.2.53, 198.51.100.53',
        '',
        '[Peer]',
        'PublicKey = ' . $data['server_public_key'],
        'AllowedIPs = 192.0.2.0/24, 198.51.100.0/24',
        'Endpoint = vpn.example.test:51820',
        'PersistentKeepalive = 25',
        '',
    ]);

    wgce_assert_sensitive_same(
        $expected,
        wgclientexport_render_client_config($data),
        'Rendered client configuration differs from the canonical form'
    );
});

wgce_test('renderer omits optional DNS and zero keepalive', static function (): void {
    $rendered = wgclientexport_render_client_config(wgce_client_config_data([
        'dns_ipv4' => [],
        'persistent_keepalive' => '0',
        'allowed_ips' => ['0.0.0.0/0'],
    ]));

    wgce_assert_not_contains("\nDNS =", $rendered);
    wgce_assert_not_contains('PersistentKeepalive', $rendered);
    wgce_assert_contains('AllowedIPs = 0.0.0.0/0', $rendered);
    wgce_assert_true(str_ends_with($rendered, "\n"), 'Configuration must end in exactly one newline');
    wgce_assert_false(str_ends_with($rendered, "\n\n"), 'Configuration must not end in a blank line');
});

wgce_test('renderer supports split, full, and custom route results', static function (): void {
    $profiles = [
        'local' => wgclientexport_build_allowed_ips('local', ['192.0.2.0/24']),
        'full' => wgclientexport_build_allowed_ips('full'),
        'custom' => wgclientexport_build_allowed_ips('custom', [], ['203.0.113.0/24']),
    ];

    foreach ($profiles as $mode => $routes) {
        $rendered = wgclientexport_render_client_config(wgce_client_config_data([
            'allowed_ips' => $routes,
        ]));
        wgce_assert_contains(
            'AllowedIPs = ' . implode(', ', $routes),
            $rendered,
            'Rendered AllowedIPs mismatch for ' . $mode
        );
    }
});

wgce_test('renderer rejects newline injection in every configuration value class', static function (): void {
    $privateKey = wgce_synthetic_key('C');
    $cases = [
        ['private_key' => $privateKey . "\n"],
        ['endpoint_host' => "vpn.example.test\r\n"],
        ['allowed_ips' => ["192.0.2.0/24\nPostUp = id"]],
        ['dns_ipv4' => ["192.0.2.53\nMTU = 1"]],
    ];

    foreach ($cases as $overrides) {
        wgce_assert_throws(
            static fn(): string => wgclientexport_render_client_config(wgce_client_config_data($overrides)),
            InvalidArgumentException::class
        );
    }
});

wgce_test('renderer rejects IPv6, preshared-key routes, and malformed keys', static function (): void {
    wgce_assert_throws(
        static fn(): string => wgclientexport_render_client_config(wgce_client_config_data([
            'allowed_ips' => ['::/0'],
        ])),
        InvalidArgumentException::class
    );
    wgce_assert_throws(
        static fn(): string => wgclientexport_render_client_config(wgce_client_config_data([
            'private_key' => 'not-a-wireguard-key',
        ])),
        InvalidArgumentException::class
    );

    $rendered = wgclientexport_render_client_config(wgce_client_config_data([
        'preshared_key' => wgce_synthetic_key('P'),
    ]));
    wgce_assert_not_contains('PresharedKey', $rendered);
    wgce_assert_not_contains('::', $rendered);
});

wgce_test('configuration filename is deterministic and reduced to a safe basename', static function (): void {
    wgce_assert_same('Test-Phone-1.conf', wgclientexport_config_filename('Test Phone #1'));
    wgce_assert_same(
        wgclientexport_config_filename('Test Phone #1'),
        wgclientexport_config_filename('Test Phone #1')
    );

    $longName = str_repeat('A', 80);
    $filename = wgclientexport_config_filename($longName);
    wgce_assert_same(str_repeat('A', 64) . '.conf', $filename);
    wgce_assert_same(basename($filename), $filename);
    wgce_assert_not_contains('..', $filename);
});

wgce_test('configuration filename rejects traversal and control characters', static function (): void {
    foreach ([
        '',
        '   ',
        '../client',
        'parent..client',
        'directory/client',
        'directory\\client',
        "client\r.conf",
        "client\n.conf",
        "client\0.conf",
    ] as $unsafeName) {
        wgce_assert_throws(
            static fn(): string => wgclientexport_config_filename($unsafeName),
            InvalidArgumentException::class
        );
    }
});

wgce_test('renderer independently enforces route and DNS count limits', static function (): void {
    $routes = [];
    for ($index = 0; $index < 33; ++$index) {
        $routes[] = '10.30.' . $index . '.0/24';
    }
    wgce_assert_throws(
        static fn(): string => wgclientexport_render_client_config(wgce_client_config_data([
            'allowed_ips' => $routes,
        ])),
        InvalidArgumentException::class
    );
    wgce_assert_throws(
        static fn(): string => wgclientexport_render_client_config(wgce_client_config_data([
            'dns_ipv4' => ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4', '192.0.2.5'],
        ])),
        InvalidArgumentException::class
    );
});

wgce_test('production configuration size ceiling remains 2048 bytes', static function (): void {
    wgce_assert_same(2048, WGCLIENTEXPORT_MAX_CONFIG_BYTES);
    $source = file_get_contents(
        wgce_project_root() . '/files/usr/local/pkg/wgclientexport/client_config.inc'
    );
    wgce_assert_true(is_string($source), 'Could not read client configuration renderer source');
    wgce_assert_matches(
        '/strlen\s*\(\s*\$configuration\s*\)\s*>\s*WGCLIENTEXPORT_MAX_CONFIG_BYTES/',
        $source,
        'Renderer does not enforce the configured byte ceiling'
    );
});

wgce_test_run();
