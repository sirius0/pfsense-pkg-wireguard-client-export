<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

$GLOBALS['wgce_interface_state'] = [
    'assigned' => [],
    'interfaces' => [],
    'addresses' => [],
    'prefixes' => [],
];
$GLOBALS['wgce_wireguard_state'] = [];

function wgce_reset_wireguard_state(): void
{
    $GLOBALS['wgce_wireguard_state'] = [
        'wgg' => ['tunnels' => [], 'peers' => []],
        'peers' => [],
        'running_keys' => [],
        'service_enabled' => true,
        'service_running' => true,
        'post_response' => ['input_errors' => [], 'changes' => false],
        'sync_response' => ['ret_code' => 0, 'tunnels' => []],
    ];
}

function wg_globals(): void
{
    global $wgg;
    $wgg = $GLOBALS['wgce_wireguard_state']['wgg'];
}

function wg_do_peer_post(array $post): array
{
    return $GLOBALS['wgce_wireguard_state']['post_response'];
}

function wg_tunnel_sync(
    array $tunnelNames,
    bool $restartServices = false,
    bool $resolveEndpoints = true,
    bool $json = false
): array {
    return $GLOBALS['wgce_wireguard_state']['sync_response'];
}

function wg_delete_peer(int $peerIndex): array
{
    foreach ($GLOBALS['wgce_wireguard_state']['peers'] as $tunnel => $entries) {
        $GLOBALS['wgce_wireguard_state']['peers'][$tunnel] = array_values(array_filter(
            $entries,
            static fn(array $entry): bool => (int) $entry[0] !== $peerIndex
        ));
    }
    return ['input_errors' => [], 'changes' => true];
}

function wg_tunnel_get_config_by_name(string $tunnel): false
{
    return false;
}

function wg_tunnel_get_peers_config(string $tunnel): array
{
    return $GLOBALS['wgce_wireguard_state']['peers'][$tunnel] ?? [];
}

function wg_tunnel_get_peers_running_keys(string $tunnel): array
{
    return $GLOBALS['wgce_wireguard_state']['running_keys'][$tunnel] ?? [];
}

function wg_gen_keypair(bool $json = false): array
{
    return ['privkey' => wgce_synthetic_key('C'), 'pubkey' => wgce_synthetic_key('P')];
}

function wg_is_service_enabled(): bool
{
    return $GLOBALS['wgce_wireguard_state']['service_enabled'];
}

function wg_is_service_running(): bool
{
    return $GLOBALS['wgce_wireguard_state']['service_running'];
}

function is_wg_tunnel_assigned(string $name): bool
{
    return !empty($GLOBALS['wgce_interface_state']['assigned'][$name]);
}

function wg_get_pfsense_interface_info(string $name): mixed
{
    return $GLOBALS['wgce_interface_state']['interfaces'][$name] ?? false;
}

function get_interface_ip(string $name): mixed
{
    return $GLOBALS['wgce_interface_state']['addresses'][$name] ?? null;
}

function get_interface_subnet(string $name): mixed
{
    return $GLOBALS['wgce_interface_state']['prefixes'][$name] ?? null;
}

wgce_reset_wireguard_state();

wgce_require_modules([
    'files/usr/local/pkg/wgclientexport/validation.inc',
    'files/usr/local/pkg/wgclientexport/ip_allocator.inc',
    'files/usr/local/pkg/wgclientexport/wireguard_adapter.inc',
]);

wgce_test('allocator excludes network and broadcast boundaries', static function (): void {
    wgce_assert_same('10.20.30.1', wgclientexport_allocate_ipv4('10.20.30.0/29'));
    wgce_assert_false(wgclientexport_address_is_available('10.20.30.0', '10.20.30.0/29'));
    wgce_assert_false(wgclientexport_address_is_available('10.20.30.7', '10.20.30.0/29'));
    wgce_assert_true(wgclientexport_address_is_available('10.20.30.1', '10.20.30.0/29'));
});

wgce_test('allocator chooses the lowest address after used ranges and reservations', static function (): void {
    $actual = wgclientexport_allocate_ipv4(
        '10.20.30.0/29',
        ['10.20.30.0/30'],
        ['10.20.30.4/32']
    );

    wgce_assert_same('10.20.30.5', $actual);
});

wgce_test('allocator accepts official address row shapes', static function (): void {
    $actual = wgclientexport_allocate_ipv4(
        '10.20.30.0/29',
        [
            ['address' => '10.20.30.1', 'mask' => '32'],
            ['cidr' => '10.20.30.2/32'],
        ],
        [['address' => '10.20.30.3', 'mask' => 32]]
    );

    wgce_assert_same('10.20.30.4', $actual);
});

wgce_test('allocator reports pool exhaustion without returning a duplicate', static function (): void {
    $error = wgce_assert_throws(
        static fn(): string => wgclientexport_allocate_ipv4(
            '198.51.100.0/30',
            ['198.51.100.1/32'],
            ['198.51.100.2/32']
        ),
        RuntimeException::class
    );

    wgce_assert_not_contains('198.51.100.1', $error->getMessage());
    wgce_assert_not_contains('198.51.100.2', $error->getMessage());
});

wgce_test('allocator rejects pools smaller than slash 30', static function (): void {
    wgce_assert_throws(
        static fn(): string => wgclientexport_allocate_ipv4('198.51.100.0/31'),
        InvalidArgumentException::class
    );
});

wgce_test('duplicate detection understands official peer rows and tunnel scope', static function (): void {
    $peers = [
        [
            'tun' => 'tun_wg0',
            'allowedips' => ['row' => [
                ['address' => '10.20.30.2', 'mask' => '32'],
            ]],
        ],
        [
            'tun' => 'tun_wg1',
            'allowed_ips' => ['10.20.30.3/32'],
        ],
    ];

    wgce_assert_same(
        '10.20.30.2/32',
        wgclientexport_find_duplicate_allowed_ip(['10.20.30.2/32'], $peers, 'tun_wg0')
    );
    wgce_assert_same(
        null,
        wgclientexport_find_duplicate_allowed_ip(['10.20.30.3/32'], $peers, 'tun_wg0')
    );
    wgce_assert_same(
        '10.20.30.3/32',
        wgclientexport_find_duplicate_allowed_ip(['10.20.30.3/32'], $peers, 'tun_wg1')
    );
});

wgce_test('assigned tunnel uses live pfSense interface address instead of stale rows', static function (): void {
    $GLOBALS['wgce_interface_state'] = [
        'assigned' => ['tun_wg0' => true],
        'interfaces' => ['tun_wg0' => ['name' => 'opt7']],
        'addresses' => ['opt7' => '10.77.0.1'],
        'prefixes' => ['opt7' => '24'],
    ];
    $tunnel = [
        'name' => 'tun_wg0',
        'addresses' => ['row' => [
            ['address' => '192.0.2.99', 'mask' => '24'],
        ]],
    ];

    wgce_assert_same(
        ['row' => [['address' => '10.77.0.1', 'mask' => '24']]],
        wgclientexport_wireguard_tunnel_addresses($tunnel)
    );
});

wgce_test('unassigned tunnel preserves normalized configured address rows', static function (): void {
    $GLOBALS['wgce_interface_state'] = [
        'assigned' => ['tun_wg1' => false],
        'interfaces' => [],
        'addresses' => [],
        'prefixes' => [],
    ];
    $first = ['address' => '10.88.0.1', 'mask' => '24'];
    $second = ['address' => '10.89.0.1', 'mask' => '24'];
    $tunnel = [
        'name' => 'tun_wg1',
        'addresses' => ['row' => [4 => $first, 9 => 'invalid-row', 12 => $second]],
    ];

    wgce_assert_same(
        ['row' => [$first, $second]],
        wgclientexport_wireguard_tunnel_addresses($tunnel)
    );
    wgce_assert_same(
        ['row' => [$first]],
        wgclientexport_wireguard_tunnel_addresses([
            'name' => 'tun_wg1',
            'addresses' => ['row' => $first],
        ])
    );
});

wgce_test('assigned tunnel with unavailable interface state fails closed', static function (): void {
    $tunnel = [
        'name' => 'tun_wg2',
        'addresses' => ['row' => [
            ['address' => '10.99.0.1', 'mask' => '24'],
        ]],
    ];

    $GLOBALS['wgce_interface_state'] = [
        'assigned' => ['tun_wg2' => true],
        'interfaces' => ['tun_wg2' => false],
        'addresses' => [],
        'prefixes' => [],
    ];
    wgce_assert_same(['row' => []], wgclientexport_wireguard_tunnel_addresses($tunnel));

    $GLOBALS['wgce_interface_state'] = [
        'assigned' => ['tun_wg2' => true],
        'interfaces' => ['tun_wg2' => ['name' => 'opt8']],
        'addresses' => ['opt8' => ''],
        'prefixes' => ['opt8' => '24'],
    ];
    wgce_assert_same(['row' => []], wgclientexport_wireguard_tunnel_addresses($tunnel));
});

wgce_test('sync succeeds only when the requested tunnel is processed while service stays running', static function (): void {
    wgce_reset_wireguard_state();
    $GLOBALS['wgce_wireguard_state']['sync_response'] = [
        'ret_code' => 0,
        'tunnels' => [['name' => 'tun_wg1', 'ret_code' => 0]],
    ];
    $wrongTunnel = wgclientexport_wireguard_sync_tunnel('tun_wg0');
    wgce_assert_false($wrongTunnel['processed']);
    wgce_assert_true($wrongTunnel['ret_code'] !== 0);

    $GLOBALS['wgce_wireguard_state']['sync_response'] = [
        'ret_code' => 0,
        'tunnels' => [['name' => 'tun_wg0', 'ret_code' => 0]],
    ];
    $success = wgclientexport_wireguard_sync_tunnel('tun_wg0');
    wgce_assert_true($success['processed']);
    wgce_assert_same(0, $success['ret_code']);

    $GLOBALS['wgce_wireguard_state']['service_running'] = false;
    $stopped = wgclientexport_wireguard_sync_tunnel('tun_wg0');
    wgce_assert_false($stopped['processed']);
    wgce_assert_true($stopped['ret_code'] !== 0);
});

wgce_test('peer confirmation requires exact persistent state and the runtime public key', static function (): void {
    wgce_reset_wireguard_state();
    $publicKey = wgce_synthetic_key('P');
    $identity = ['tunnel' => 'tun_wg0', 'public_key' => $publicKey, 'index' => 7];
    $peer = [
        'tun' => 'tun_wg0',
        'descr' => 'test-client',
        'enabled' => 'yes',
        'endpoint' => '',
        'port' => '',
        'publickey' => $publicKey,
        'allowedips' => ['row' => [['address' => '10.77.0.2', 'mask' => '32']]],
    ];
    $GLOBALS['wgce_wireguard_state']['peers']['tun_wg0'] = [[7, $peer]];
    $GLOBALS['wgce_wireguard_state']['running_keys']['tun_wg0'] = [$publicKey];

    wgce_assert_true(wgclientexport_wireguard_confirm_peer($identity, '10.77.0.2'));
    $GLOBALS['wgce_wireguard_state']['running_keys']['tun_wg0'] = [];
    wgce_assert_false(wgclientexport_wireguard_confirm_peer($identity, '10.77.0.2'));
    $GLOBALS['wgce_wireguard_state']['running_keys']['tun_wg0'] = [$publicKey];
    $GLOBALS['wgce_wireguard_state']['peers']['tun_wg0'][0][1]['allowedips']['row'][0]['mask'] = '24';
    wgce_assert_false(wgclientexport_wireguard_confirm_peer($identity, '10.77.0.2'));
});

wgce_test('rollback absence requires both persistent and runtime peer removal', static function (): void {
    wgce_reset_wireguard_state();
    $publicKey = wgce_synthetic_key('P');
    $identity = ['tunnel' => 'tun_wg0', 'public_key' => $publicKey, 'index' => 7];
    $GLOBALS['wgce_wireguard_state']['peers']['tun_wg0'] = [[7, [
        'tun' => 'tun_wg0',
        'endpoint' => '',
        'port' => '',
        'publickey' => $publicKey,
        'allowedips' => ['row' => [['address' => '10.77.0.2', 'mask' => '32']]],
    ]]];
    $GLOBALS['wgce_wireguard_state']['running_keys']['tun_wg0'] = [$publicKey];

    $deleted = wgclientexport_wireguard_delete_peer($identity);
    wgce_assert_true($deleted['persistent_absent']);
    wgce_assert_false(wgclientexport_wireguard_confirm_peer_absent($identity));

    $GLOBALS['wgce_wireguard_state']['running_keys']['tun_wg0'] = [];
    wgce_assert_true(wgclientexport_wireguard_confirm_peer_absent($identity));
});

wgce_test('changed post retains rollback identity when persistent lookup fails', static function (): void {
    wgce_reset_wireguard_state();
    $publicKey = wgce_synthetic_key('P');
    $GLOBALS['wgce_wireguard_state']['post_response'] = [
        'input_errors' => [],
        'changes' => true,
    ];

    $created = wgclientexport_wireguard_create_peer([
        'tunnel' => 'tun_wg0',
        'client_name' => 'ambiguous-create',
        'public_key' => $publicKey,
        'address' => '10.77.0.2',
    ]);

    wgce_assert_true($created['changes']);
    wgce_assert_true($created['input_errors'] !== []);
    wgce_assert_same(
        ['tunnel' => 'tun_wg0', 'public_key' => $publicKey, 'index' => null],
        $created['identity']
    );
});

wgce_test_run();
