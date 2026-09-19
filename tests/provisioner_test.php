<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

$GLOBALS['wgce_config_backend'] = ['value' => null, 'sets' => [], 'writes' => []];

function config_get_path(string $path, mixed $default = null): mixed
{
    return $GLOBALS['wgce_config_backend']['value'] ?? $default;
}

function config_set_path(string $path, mixed $value): mixed
{
    $GLOBALS['wgce_config_backend']['sets'][] = ['path' => $path, 'value' => $value];
    $result = $GLOBALS['wgce_config_backend']['set_result'] ?? null;
    if ($result !== false && $result !== -1) {
        $GLOBALS['wgce_config_backend']['value'] = $value;
    }
    return $result;
}

function write_config(string $message): mixed
{
    $GLOBALS['wgce_config_backend']['writes'][] = $message;
    return $GLOBALS['wgce_config_backend']['write_result'] ?? null;
}

wgce_require_modules([
    'files/usr/local/pkg/wgclientexport/validation.inc',
    'files/usr/local/pkg/wgclientexport/config.inc',
    'files/usr/local/pkg/wgclientexport/ip_allocator.inc',
    'files/usr/local/pkg/wgclientexport/client_config.inc',
    'files/usr/local/pkg/wgclientexport/wireguard_adapter.inc',
    'files/usr/local/pkg/wgclientexport/provisioner.inc',
]);

function wgce_provision_request(array $overrides = []): array
{
    return array_replace([
        'tunnel' => 'tun_wg0',
        'client_name' => 'test-laptop',
        'routing_profile' => 'full',
    ], $overrides);
}

function wgce_provision_settings(array $overrides = []): array
{
    return array_replace([
        'enabled' => 'yes',
        'client_pool_ipv4' => '10.77.0.0/24',
        'endpoint_host' => 'vpn.example.test',
        'endpoint_port' => '51820',
        'dns_ipv4' => ['192.0.2.53'],
        'persistent_keepalive' => '25',
        'local_routes_ipv4' => ['192.0.2.0/24'],
        'reservations_ipv4' => [],
    ], $overrides);
}

function wgce_provision_tunnel(): array
{
    return [
        'name' => 'tun_wg0',
        'enabled' => true,
        'public_key' => wgce_synthetic_key('S'),
        'addresses' => ['row' => [
            ['address' => '10.77.0.1', 'mask' => '24'],
        ]],
    ];
}

/** @return array{deps: array<string, mixed>, events: ArrayObject, private_key: string} */
function wgce_provision_dependencies(string $suffix): array
{
    $events = new ArrayObject();
    $privateKey = wgce_synthetic_key('C');
    $publicKey = wgce_synthetic_key('P');
    $lockPath = sys_get_temp_dir() . '/wgclientexport-test-' . getmypid() . '-' . $suffix . '.lock';
    @unlink($lockPath);

    $deps = [
        'settings' => wgce_provision_settings(),
        'lock_path' => $lockPath,
        'lock_timeout' => 0.2,
        'load' => static function () use ($events): bool {
            $events[] = 'load';
            return true;
        },
        'get_tunnel' => static function (string $tunnel) use ($events): array {
            $events[] = 'get_tunnel:' . $tunnel;
            return wgce_provision_tunnel();
        },
        'get_peers' => static function (string $tunnel) use ($events): array {
            $events[] = 'get_peers:' . $tunnel;
            return [];
        },
        'keypair' => static function () use ($events, $privateKey, $publicKey): array {
            $events[] = 'keypair';
            return ['private_key' => $privateKey, 'public_key' => $publicKey];
        },
        'create_peer' => static function (array $peer) use ($events, $publicKey): array {
            $events[] = ['create_peer', $peer];
            return [
                'input_errors' => [],
                'changes' => true,
                'identity' => ['tunnel' => 'tun_wg0', 'public_key' => $publicKey, 'index' => 7],
            ];
        },
        'sync_tunnel' => static function (string $tunnel) use ($events): array {
            $events[] = 'sync:' . $tunnel;
            return ['ret_code' => 0];
        },
        'confirm_peer' => static function (array $identity, string $address) use ($events): bool {
            $events[] = ['confirm_peer', $identity, $address];
            return true;
        },
        'delete_peer' => static function (array $identity) use ($events): array {
            $events[] = ['delete_peer', $identity];
            return ['input_errors' => [], 'changes' => true];
        },
        'confirm_peer_absent' => static function (array $identity) use ($events): bool {
            $events[] = ['confirm_peer_absent', $identity];
            return true;
        },
    ];

    return ['deps' => $deps, 'events' => $events, 'private_key' => $privateKey];
}

function wgce_assert_lock_released(string $path): void
{
    $handle = fopen($path, 'c');
    wgce_assert_true(is_resource($handle), 'Expected test lock file to remain openable');
    $locked = flock($handle, LOCK_EX | LOCK_NB);
    if ($locked) {
        flock($handle, LOCK_UN);
    }
    fclose($handle);
    @unlink($path);
    wgce_assert_true($locked, 'Provisioner did not release its per-tunnel lock');
}

wgce_test('peer payload is dynamic and contains no client private material', static function (): void {
    $publicKey = wgce_synthetic_key('P');
    $clientPrivateKey = wgce_synthetic_key('C');
    $payload = wgclientexport_build_peer_payload([
        'tunnel' => 'tun_wg0',
        'client_name' => 'test-phone',
        'public_key' => $publicKey,
        'address' => '10.77.0.2/32',
    ]);

    wgce_assert_same('yes', $payload['dynamic']);
    wgce_assert_same('', $payload['endpoint']);
    wgce_assert_same('', $payload['port']);
    wgce_assert_same('', $payload['presharedkey']);
    wgce_assert_same('10.77.0.2', $payload['address0']);
    wgce_assert_same('32', $payload['address_subnet0']);
    wgce_assert_same($publicKey, $payload['publickey']);
    wgce_assert_false(str_contains(serialize($payload), $clientPrivateKey));
});

wgce_test('successful provision creates, applies, confirms, and returns one-time configuration', static function (): void {
    $fixture = wgce_provision_dependencies('success');
    $result = wgclientexport_provision(wgce_provision_request(), $fixture['deps']);

    wgce_assert_same(null, $result['error_code']);
    wgce_assert_true($result['changes']);
    wgce_assert_same('10.77.0.2/32', $result['result']['address']);
    wgce_assert_same('test-laptop.conf', $result['result']['filename']);
    wgce_assert_true(
        str_contains($result['result']['configuration'], $fixture['private_key']),
        'One-time client configuration does not contain the generated synthetic private key'
    );
    wgce_assert_false(array_key_exists('private_key', $result['result']));

    $events = $fixture['events']->getArrayCopy();
    wgce_assert_same('load', $events[0]);
    wgce_assert_same('get_tunnel:tun_wg0', $events[1]);
    wgce_assert_same('get_peers:tun_wg0', $events[2]);
    wgce_assert_same('keypair', $events[3]);
    wgce_assert_same('get_peers:tun_wg0', $events[4]);
    wgce_assert_same('create_peer', $events[5][0]);
    wgce_assert_false(
        str_contains(serialize($events[5][1]), $fixture['private_key']),
        'Private key was passed to the persistent peer mutation boundary'
    );
    wgce_assert_same('sync:tun_wg0', $events[6]);
    wgce_assert_same('confirm_peer', $events[7][0]);
    wgce_assert_lock_released($fixture['deps']['lock_path']);
});

wgce_test('client pool may be a proper tunnel subnet that excludes the interface address', static function (): void {
    $fixture = wgce_provision_dependencies('contained-subnet');
    $fixture['deps']['settings'] = wgce_provision_settings([
        'client_pool_ipv4' => '10.77.0.128/25',
    ]);

    $result = wgclientexport_provision(wgce_provision_request(), $fixture['deps']);

    wgce_assert_same(null, $result['error_code']);
    wgce_assert_true($result['changes']);
    wgce_assert_same('10.77.0.129/32', $result['result']['address']);
    $eventNames = array_map(
        static fn(mixed $event): string => is_array($event) ? (string) $event[0] : (string) $event,
        $fixture['events']->getArrayCopy()
    );
    wgce_assert_true(in_array('keypair', $eventNames, true), 'Contained pool did not reach key generation');
    wgce_assert_true(in_array('create_peer', $eventNames, true), 'Contained pool did not reach peer creation');
    wgce_assert_lock_released($fixture['deps']['lock_path']);
});

wgce_test('supernet and unrelated pools fail before key generation or mutation', static function (): void {
    foreach ([
        'supernet' => '10.76.0.0/15',
        'unrelated' => '10.88.0.0/24',
    ] as $case => $pool) {
        $fixture = wgce_provision_dependencies('pool-' . $case);
        $fixture['deps']['settings'] = wgce_provision_settings([
            'client_pool_ipv4' => $pool,
        ]);

        $result = wgclientexport_provision(wgce_provision_request(), $fixture['deps']);

        wgce_assert_same('pool_mismatch', $result['error_code'], 'Unexpected result for ' . $case . ' pool');
        wgce_assert_false($result['changes']);
        wgce_assert_same(null, $result['result']);
        wgce_assert_same(
            ['load', 'get_tunnel:tun_wg0'],
            $fixture['events']->getArrayCopy(),
            ucfirst($case) . ' pool reached key generation or mutation'
        );
        wgce_assert_lock_released($fixture['deps']['lock_path']);
    }
});

wgce_test('peer name and address are revalidated from a second snapshot before mutation', static function (): void {
    $changedPeers = [
        'name' => [[
            'descr' => 'test-laptop',
            'allowedips' => ['row' => [['address' => '10.77.0.50', 'mask' => '32']]],
        ]],
        'address' => [[
            'descr' => 'another-client',
            'allowedips' => ['row' => [['address' => '10.77.0.2', 'mask' => '32']]],
        ]],
    ];

    foreach ($changedPeers as $case => $secondSnapshot) {
        $fixture = wgce_provision_dependencies('revalidate-' . $case);
        $reads = 0;
        $fixture['deps']['get_peers'] = static function (string $tunnel) use (
            &$reads,
            $secondSnapshot,
            $fixture
        ): array {
            ++$reads;
            $fixture['events'][] = 'get_peers:' . $reads;
            return $reads === 1 ? [] : $secondSnapshot;
        };

        $result = wgclientexport_provision(wgce_provision_request(), $fixture['deps']);

        wgce_assert_same('concurrent_conflict', $result['error_code'], 'Unexpected result for changed ' . $case);
        wgce_assert_same(2, $reads);
        wgce_assert_same(
            ['load', 'get_tunnel:tun_wg0', 'get_peers:1', 'keypair', 'get_peers:2'],
            $fixture['events']->getArrayCopy(),
            'Changed ' . $case . ' was not checked immediately before mutation'
        );
        wgce_assert_same(null, $result['result']);
        wgce_assert_lock_released($fixture['deps']['lock_path']);
    }
});

wgce_test('apply failure deletes the exact peer and reapplies original runtime state', static function (): void {
    $fixture = wgce_provision_dependencies('rollback');
    $syncCalls = 0;
    $fixture['deps']['sync_tunnel'] = static function (string $tunnel) use (&$syncCalls, $fixture): array {
        ++$syncCalls;
        $fixture['events'][] = 'sync:' . $tunnel . ':' . $syncCalls;
        return ['ret_code' => $syncCalls === 1 ? 1 : 0];
    };

    $result = wgclientexport_provision(wgce_provision_request(), $fixture['deps']);

    wgce_assert_same('apply_failed', $result['error_code']);
    wgce_assert_same(true, $result['rollback']);
    wgce_assert_same(null, $result['result']);
    wgce_assert_false($result['changes']);
    wgce_assert_same(2, $syncCalls);

    $deleteEvents = array_values(array_filter(
        $fixture['events']->getArrayCopy(),
        static fn(mixed $event): bool => is_array($event) && $event[0] === 'delete_peer'
    ));
    wgce_assert_same(1, count($deleteEvents));
    wgce_assert_same(7, $deleteEvents[0][1]['index']);
    $rollbackTail = array_slice($fixture['events']->getArrayCopy(), -3);
    wgce_assert_same('delete_peer', $rollbackTail[0][0]);
    wgce_assert_same('sync:tun_wg0:2', $rollbackTail[1]);
    wgce_assert_same('confirm_peer_absent', $rollbackTail[2][0]);
    wgce_assert_same(7, $rollbackTail[2][1]['index']);
    wgce_assert_lock_released($fixture['deps']['lock_path']);
});

wgce_test('confirmation mismatch follows the same confirmed rollback path', static function (): void {
    $fixture = wgce_provision_dependencies('confirm-rollback');
    $syncCalls = 0;
    $fixture['deps']['sync_tunnel'] = static function (string $tunnel) use (&$syncCalls): array {
        ++$syncCalls;
        return ['ret_code' => 0];
    };
    $fixture['deps']['confirm_peer'] = static fn(array $identity, string $address): bool => false;

    $result = wgclientexport_provision(wgce_provision_request(), $fixture['deps']);

    wgce_assert_same('apply_failed', $result['error_code']);
    wgce_assert_same(true, $result['rollback']);
    wgce_assert_same(null, $result['result']);
    wgce_assert_same(2, $syncCalls);
    $deleteCount = count(array_filter(
        $fixture['events']->getArrayCopy(),
        static fn(mixed $event): bool => is_array($event) && $event[0] === 'delete_peer'
    ));
    wgce_assert_same(1, $deleteCount);
    wgce_assert_lock_released($fixture['deps']['lock_path']);
});

wgce_test('rollback failure is explicit and never returns a credential', static function (): void {
    $fixture = wgce_provision_dependencies('rollback-failed');
    $fixture['deps']['sync_tunnel'] = static fn(string $tunnel): array => ['ret_code' => 1];
    $fixture['deps']['delete_peer'] = static fn(array $identity): array => [
        'input_errors' => ['synthetic deletion failure'],
        'changes' => false,
    ];

    $result = wgclientexport_provision(wgce_provision_request(), $fixture['deps']);

    wgce_assert_same('rollback_failed', $result['error_code']);
    wgce_assert_same(false, $result['rollback']);
    wgce_assert_same(null, $result['result']);
    wgce_assert_false(str_contains(serialize($result), $fixture['private_key']));
    wgce_assert_lock_released($fixture['deps']['lock_path']);
});

wgce_test('validation failure performs no key generation or mutation', static function (): void {
    $fixture = wgce_provision_dependencies('validation');
    $result = wgclientexport_provision(wgce_provision_request([
        'client_name' => "invalid\nname",
    ]), $fixture['deps']);

    wgce_assert_same('validation_failed', $result['error_code']);
    wgce_assert_same([], $fixture['events']->getArrayCopy());
    wgce_assert_same(null, $result['result']);
    wgce_assert_false(is_file($fixture['deps']['lock_path']), 'Validation should fail before lock creation');
});

wgce_test('settings persistence rejects nested private keys before configuration APIs run', static function (): void {
    $settings = wgce_provision_settings([
        'metadata' => ['client_private_key' => wgce_synthetic_key('C')],
    ]);
    $result = wgclientexport_save_settings($settings);

    wgce_assert_false($result['saved']);
    wgce_assert_false($result['changes']);
    wgce_assert_same(null, $result['result']);
    wgce_assert_true($result['input_errors'] !== []);
});

wgce_test('saving one tunnel upserts it without deleting existing tunnel settings', static function (): void {
    $existing = wgclientexport_normalize_tunnel_settings(wgce_provision_settings([
        'tunnel_id' => 'tun_wg0',
    ]))['result'];
    $existing['legacy_ui_note'] = 'must-not-survive-normalization';
    $GLOBALS['wgce_config_backend'] = [
        'value' => ['schema_version' => '1', 'tunnels' => ['item' => [$existing]]],
        'sets' => [],
        'writes' => [],
    ];

    $newSettings = wgce_provision_settings([
        'tunnel_id' => 'tun_wg1',
        'client_pool_ipv4' => '10.88.0.0/24',
        'endpoint_host' => 'second-vpn.example.test',
    ]);
    $result = wgclientexport_save_settings($newSettings);

    wgce_assert_true($result['saved']);
    wgce_assert_true($result['changes']);
    wgce_assert_same(
        ['tun_wg0', 'tun_wg1'],
        array_column($result['result']['tunnels']['item'], 'tunnel_id')
    );
    wgce_assert_same(
        [
            'tunnel_id', 'enabled', 'client_pool_ipv4', 'endpoint_host', 'endpoint_port',
            'dns_ipv4', 'persistent_keepalive', 'local_routes_ipv4', 'reservations_ipv4',
        ],
        array_keys($result['result']['tunnels']['item'][0]),
        'Preserved legacy settings were not reduced to the explicit whitelist'
    );
    wgce_assert_same(1, count($GLOBALS['wgce_config_backend']['sets']));
    wgce_assert_same(1, count($GLOBALS['wgce_config_backend']['writes']));
});

wgce_test('settings reject excessive local routes and DNS resolvers without persistence', static function (): void {
    $routes = [];
    for ($index = 0; $index < 33; ++$index) {
        $routes[] = '10.40.' . $index . '.0/24';
    }
    $GLOBALS['wgce_config_backend'] = ['value' => null, 'sets' => [], 'writes' => []];
    $settings = wgce_provision_settings([
        'tunnel_id' => 'tun_wg0',
        'local_routes_ipv4' => $routes,
        'dns_ipv4' => ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4', '192.0.2.5'],
    ]);

    $result = wgclientexport_save_settings($settings);

    wgce_assert_false($result['saved']);
    wgce_assert_false($result['changes']);
    wgce_assert_same(null, $result['result']);
    wgce_assert_true(count($result['input_errors']) >= 2, 'Expected route and DNS limit errors');
    wgce_assert_same([], $GLOBALS['wgce_config_backend']['sets']);
    wgce_assert_same([], $GLOBALS['wgce_config_backend']['writes']);
});

wgce_test('secret-bearing preserved settings are scrubbed during a valid upsert', static function (): void {
    $existing = wgclientexport_normalize_tunnel_settings(wgce_provision_settings([
        'tunnel_id' => 'tun_wg0',
    ]))['result'];
    $existing['legacy_private_key'] = wgce_synthetic_key('L');
    $GLOBALS['wgce_config_backend'] = [
        'value' => ['schema_version' => '1', 'tunnels' => ['item' => [$existing]]],
        'sets' => [],
        'writes' => [],
    ];

    $result = wgclientexport_save_settings(wgce_provision_settings([
        'tunnel_id' => 'tun_wg1',
        'client_pool_ipv4' => '10.88.0.0/24',
    ]));

    wgce_assert_true($result['saved']);
    wgce_assert_true($result['changes']);
    wgce_assert_same(
        ['tun_wg0', 'tun_wg1'],
        array_column($result['result']['tunnels']['item'], 'tunnel_id')
    );
    wgce_assert_false(wgclientexport_contains_secret_field($result['result']));
    wgce_assert_false(str_contains(serialize($result), wgce_synthetic_key('L')));
    wgce_assert_same(1, count($GLOBALS['wgce_config_backend']['sets']));
    wgce_assert_same(1, count($GLOBALS['wgce_config_backend']['writes']));
    wgce_assert_false(wgclientexport_contains_secret_field(
        $GLOBALS['wgce_config_backend']['value']
    ));
});

wgce_test('pfSense configuration write failure sentinels are never reported as saved', static function (): void {
    $cases = [
        ['set_result' => false, 'write_result' => null],
        ['set_result' => -1, 'write_result' => null],
        ['set_result' => null, 'write_result' => false],
        ['set_result' => null, 'write_result' => -1],
    ];

    foreach ($cases as $case) {
        $GLOBALS['wgce_config_backend'] = [
            'value' => null,
            'sets' => [],
            'writes' => [],
            'set_result' => $case['set_result'],
            'write_result' => $case['write_result'],
        ];
        $result = wgclientexport_save_settings(wgce_provision_settings([
            'tunnel_id' => 'tun_wg0',
        ]));

        wgce_assert_false($result['saved']);
        wgce_assert_false($result['changes']);
        wgce_assert_same(null, $result['result']);
        wgce_assert_true($result['input_errors'] !== []);
    }
});

wgce_test_run();
