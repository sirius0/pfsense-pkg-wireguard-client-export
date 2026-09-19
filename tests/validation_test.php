<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
wgce_require_modules([
    'files/usr/local/pkg/wgclientexport/validation.inc',
]);

function wgce_valid_request(array $overrides = []): array
{
    return array_replace([
        'tunnel' => 'tun_wg0',
        'client_name' => 'test-phone',
        'client_pool_ipv4' => '10.77.0.0/24',
        'endpoint_host' => 'vpn.example.test',
        'endpoint_port' => '51820',
        'routing_profile' => 'local',
        'local_routes_ipv4' => ['192.0.2.0/24', '198.51.100.0/24'],
        'custom_routes_ipv4' => [],
        'persistent_keepalive' => '25',
        'dns_ipv4' => ['192.0.2.53'],
    ], $overrides);
}

wgce_test('a complete IPv4 client request is valid', static function (): void {
    wgce_assert_same([], wgclientexport_validate_client_request(wgce_valid_request()));
});

wgce_test('full tunnel maps only to the IPv4 default route', static function (): void {
    wgce_assert_same(['0.0.0.0/0'], wgclientexport_build_allowed_ips('full'));
});

wgce_test('local routes are canonicalized and de-duplicated in first-seen order', static function (): void {
    wgce_assert_same(
        ['192.0.2.0/24', '10.0.0.0/8'],
        wgclientexport_build_allowed_ips(
            'local',
            ['192.0.2.42/24', '10.20.30.40/8', '192.0.2.0/24']
        )
    );
});

wgce_test('custom routes are used instead of local routes', static function (): void {
    wgce_assert_same(
        ['203.0.113.0/24'],
        wgclientexport_build_allowed_ips(
            'custom',
            ['192.0.2.0/24'],
            ['203.0.113.19/24']
        )
    );
});

wgce_test('local and custom profiles reject an empty route list', static function (): void {
    wgce_assert_throws(
        static fn(): array => wgclientexport_build_allowed_ips('local'),
        InvalidArgumentException::class
    );
    wgce_assert_throws(
        static fn(): array => wgclientexport_build_allowed_ips('custom'),
        InvalidArgumentException::class
    );
});

wgce_test('routing rejects IPv6 and unknown profiles', static function (): void {
    wgce_assert_throws(
        static fn(): array => wgclientexport_build_allowed_ips('custom', [], ['::/0']),
        InvalidArgumentException::class
    );
    wgce_assert_throws(
        static fn(): array => wgclientexport_build_allowed_ips('unexpected'),
        InvalidArgumentException::class
    );
});

wgce_test('validation rejects line breaks and malformed trusted-looking inputs', static function (): void {
    $errors = wgclientexport_validate_client_request(wgce_valid_request([
        'tunnel' => "tun_wg0\ninvalid",
        'client_name' => "phone\nInjected = yes",
        'endpoint_host' => "vpn.example.test\r\nInjected: yes",
        'endpoint_port' => '51820;id',
    ]));

    wgce_assert_true(count($errors) >= 4, 'Expected separate errors for tunnel, name, endpoint, and port');
});

wgce_test('validation enforces IPv4 DNS and keepalive bounds', static function (): void {
    wgce_assert_same([], wgclientexport_validate_client_request(wgce_valid_request([
        'persistent_keepalive' => '65535',
    ])));

    $errors = wgclientexport_validate_client_request(wgce_valid_request([
        'persistent_keepalive' => '65536',
        'dns_ipv4' => ['2001:db8::53'],
    ]));
    wgce_assert_true(count($errors) >= 2, 'Expected keepalive and IPv6 DNS errors');
});

wgce_test('validation rejects too-small and non-IPv4 client pools', static function (): void {
    foreach (['10.77.0.0/31', '2001:db8::/64', 'not-a-pool'] as $pool) {
        $errors = wgclientexport_validate_client_request(wgce_valid_request([
            'client_pool_ipv4' => $pool,
        ]));
        wgce_assert_true($errors !== [], 'Expected invalid pool to be rejected: ' . $pool);
    }
});

wgce_test('routing rejects more than 32 unique IPv4 routes', static function (): void {
    $routes = [];
    for ($index = 0; $index < 33; ++$index) {
        $routes[] = '10.20.' . $index . '.0/24';
    }

    wgce_assert_throws(
        static fn(): array => wgclientexport_build_allowed_ips('custom', [], $routes),
        InvalidArgumentException::class
    );
    $errors = wgclientexport_validate_client_request(wgce_valid_request([
        'routing_profile' => 'custom',
        'custom_routes_ipv4' => $routes,
    ]));
    wgce_assert_true($errors !== [], 'Request validation accepted more than 32 routes');
});

wgce_test('validation rejects more than four DNS resolvers', static function (): void {
    $errors = wgclientexport_validate_client_request(wgce_valid_request([
        'dns_ipv4' => ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4', '192.0.2.5'],
    ]));

    wgce_assert_true($errors !== [], 'Request validation accepted more than four DNS resolvers');
});

wgce_test_run();
