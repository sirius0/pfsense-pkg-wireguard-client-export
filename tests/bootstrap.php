<?php

declare(strict_types=1);

final class WgceTestFailure extends RuntimeException
{
}

final class WgceTestSkip extends RuntimeException
{
}

/** @var array<int, array{name: string, test: callable}> */
$GLOBALS['wgce_tests'] = [];

function wgce_test(string $name, callable $test): void
{
    $GLOBALS['wgce_tests'][] = ['name' => $name, 'test' => $test];
}

function wgce_assert_true(bool $condition, string $message = 'Expected condition to be true'): void
{
    if (!$condition) {
        throw new WgceTestFailure($message);
    }
}

function wgce_assert_false(bool $condition, string $message = 'Expected condition to be false'): void
{
    wgce_assert_true(!$condition, $message);
}

function wgce_assert_same(mixed $expected, mixed $actual, string $message = ''): void
{
    if ($expected !== $actual) {
        $detail = sprintf(
            'Expected %s, got %s',
            var_export($expected, true),
            var_export($actual, true)
        );
        throw new WgceTestFailure($message === '' ? $detail : $message . ': ' . $detail);
    }
}

function wgce_assert_contains(string $needle, string $haystack, string $message = ''): void
{
    if (!str_contains($haystack, $needle)) {
        throw new WgceTestFailure(
            $message === '' ? sprintf('Expected string to contain %s', var_export($needle, true)) : $message
        );
    }
}

function wgce_assert_not_contains(string $needle, string $haystack, string $message = ''): void
{
    if (str_contains($haystack, $needle)) {
        throw new WgceTestFailure(
            $message === '' ? sprintf('Expected string not to contain %s', var_export($needle, true)) : $message
        );
    }
}

function wgce_assert_matches(string $pattern, string $actual, string $message = ''): void
{
    if (preg_match($pattern, $actual) !== 1) {
        throw new WgceTestFailure(
            $message === '' ? sprintf('Expected %s to match %s', var_export($actual, true), $pattern) : $message
        );
    }
}

function wgce_assert_sensitive_same(string $expected, string $actual, string $message): void
{
    if (!hash_equals(hash('sha256', $expected), hash('sha256', $actual))) {
        throw new WgceTestFailure($message . ' (sensitive values redacted)');
    }
}

function wgce_assert_throws(callable $operation, string $expectedClass = Throwable::class): Throwable
{
    try {
        $operation();
    } catch (Throwable $error) {
        if (!is_a($error, $expectedClass)) {
            throw new WgceTestFailure(sprintf(
                'Expected exception %s, got %s: %s',
                $expectedClass,
                $error::class,
                $error->getMessage()
            ));
        }

        return $error;
    }

    throw new WgceTestFailure(sprintf('Expected exception %s, but none was thrown', $expectedClass));
}

function wgce_skip(string $reason): never
{
    throw new WgceTestSkip($reason);
}

function wgce_project_root(): string
{
    return dirname(__DIR__);
}

/** @param list<string> $relativePaths */
function wgce_require_modules(array $relativePaths): void
{
    foreach ($relativePaths as $relativePath) {
        $path = wgce_project_root() . '/' . ltrim($relativePath, '/');
        if (!is_file($path)) {
            throw new WgceTestFailure('Required module is missing: ' . $relativePath);
        }
        require_once $path;
    }
}

function wgce_synthetic_key(string $marker): string
{
    if (strlen($marker) !== 1) {
        throw new InvalidArgumentException('Synthetic key marker must be exactly one byte');
    }

    return base64_encode(str_repeat($marker, 32));
}

function wgce_contract_source(string $specificEnvironment, string $fixtureDirectory): string
{
    $roots = [];
    foreach ([$specificEnvironment, 'WGCLIENTEXPORT_WG_SOURCE_DIR'] as $environment) {
        $value = getenv($environment);
        if (is_string($value) && $value !== '') {
            $roots[] = $value;
        }
    }
    $roots[] = wgce_project_root() . '/tests/fixtures/' . $fixtureDirectory;

    foreach ($roots as $root) {
        $candidates = is_file($root) ? [$root] : [
            rtrim($root, '/') . '/wg.inc',
            rtrim($root, '/') . '/includes/wg.inc',
            rtrim($root, '/') . '/usr/local/pkg/wireguard/includes/wg.inc',
        ];
        foreach ($candidates as $candidate) {
            if (is_file($candidate) && is_readable($candidate)) {
                $source = file_get_contents($candidate);
                if ($source === false) {
                    throw new WgceTestFailure('Could not read WireGuard contract source: ' . $candidate);
                }

                $includeFiles = glob(dirname($candidate) . '/*.inc');
                if (is_array($includeFiles) && count($includeFiles) > 1) {
                    sort($includeFiles, SORT_STRING);
                    $source = '';
                    foreach ($includeFiles as $includeFile) {
                        $part = file_get_contents($includeFile);
                        if ($part === false) {
                            throw new WgceTestFailure('Could not read WireGuard contract source: ' . $includeFile);
                        }
                        $source .= "\n" . $part;
                    }
                }

                return $source;
            }
        }
    }

    wgce_skip(sprintf(
        'official wg.inc unavailable; set %s to an include directory or file',
        $specificEnvironment
    ));
}

/** @param list<string> $parameters */
function wgce_assert_function_signature(string $source, string $name, array $parameters): void
{
    $escapedParameters = array_map(
        static fn(string $parameter): string => preg_quote($parameter, '/'),
        $parameters
    );
    $signature = implode('\\s*,\\s*', $escapedParameters);
    $pattern = '/function\\s+' . preg_quote($name, '/') . '\\s*\\(\\s*' . $signature . '\\s*\\)/s';
    wgce_assert_matches($pattern, $source, 'Unexpected or missing function signature for ' . $name);
}

function wgce_test_run(): never
{
    $failures = 0;
    $skips = 0;
    $tests = $GLOBALS['wgce_tests'];

    echo 'TAP version 13' . PHP_EOL;
    echo '1..' . count($tests) . PHP_EOL;

    foreach ($tests as $index => $entry) {
        $number = $index + 1;
        try {
            $entry['test']();
            echo sprintf('ok %d - %s', $number, $entry['name']) . PHP_EOL;
        } catch (WgceTestSkip $skip) {
            ++$skips;
            echo sprintf('ok %d - %s # SKIP %s', $number, $entry['name'], $skip->getMessage()) . PHP_EOL;
        } catch (Throwable $error) {
            ++$failures;
            echo sprintf('not ok %d - %s', $number, $entry['name']) . PHP_EOL;
            echo '  ---' . PHP_EOL;
            echo '  exception: ' . $error::class . PHP_EOL;
            echo '  message: ' . str_replace(["\r", "\n"], ['\\r', '\\n'], $error->getMessage()) . PHP_EOL;
            echo '  ...' . PHP_EOL;
        }
    }

    echo sprintf('# tests=%d failures=%d skipped=%d', count($tests), $failures, $skips) . PHP_EOL;
    exit($failures === 0 ? 0 : 1);
}
