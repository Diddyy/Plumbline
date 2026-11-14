<?php

declare(strict_types=1);

/*
 * Benchmark Plumbline against real open-source Laravel apps.
 *
 *   php bench/run.php [work-dir] [app-name ...]
 *
 * Shallow-clones each app from bench/apps.json into the work directory (default bench/work),
 * scans it, and writes bench/results/<app>.json plus a summary table. Triage the findings by hand
 * and record true/false positives in BENCHMARK.md.
 *
 * If a run turns up a real vulnerability, report it privately to that project (SECURITY.md or a
 * GitHub security advisory). Never commit result files containing unreported vulnerabilities.
 */

$root = dirname(__DIR__);
$work = $argv[1] ?? $root.'/bench/work';
$only = array_slice($argv, 2);
$apps = json_decode((string) file_get_contents(__DIR__.'/apps.json'), true, flags: JSON_THROW_ON_ERROR);
is_dir($work) || mkdir($work, 0777, true);
is_dir(__DIR__.'/results') || mkdir(__DIR__.'/results', 0777, true);

$rows = [];
foreach ($apps as $app) {
    if ($only !== [] && ! in_array($app['name'], $only, true)) {
        continue;
    }
    $dir = $work.DIRECTORY_SEPARATOR.$app['name'];
    if (! is_dir($dir)) {
        passthru(sprintf('git clone --depth 1 --quiet %s %s', escapeshellarg($app['repo']), escapeshellarg($dir)), $code);
        if ($code !== 0) {
            fwrite(STDERR, "clone failed: {$app['name']}\n");
            continue;
        }
    }
    $commit = trim((string) shell_exec('git -C '.escapeshellarg($dir).' rev-parse --short HEAD'));

    $start = microtime(true);
    $out = __DIR__.'/results/'.$app['name'].'.json';
    $cmd = sprintf('%s %s scan %s --format=json --fail-on=none --output=%s',
        escapeshellarg(PHP_BINARY), escapeshellarg($root.'/bin/plumbline'), escapeshellarg($dir), escapeshellarg($out));
    exec($cmd.' 2>&1', $lines);
    $seconds = microtime(true) - $start;

    $result = json_decode((string) @file_get_contents($out), true);
    if (! is_array($result)) {
        fwrite(STDERR, "scan failed: {$app['name']}\n");
        continue;
    }
    $byRule = [];
    foreach ($result['findings'] as $finding) {
        $byRule[$finding['rule']] = ($byRule[$finding['rule']] ?? 0) + 1;
    }
    ksort($byRule);
    $rows[] = [$app['name'], $commit, $result['summary']['files'], count($result['findings']), $byRule, $seconds];
}

printf("%-20s %-9s %7s %9s %8s  %s\n", 'app', 'commit', 'files', 'findings', 'seconds', 'by rule');
foreach ($rows as [$name, $commit, $files, $count, $byRule, $seconds]) {
    $rules = implode(', ', array_map(fn ($k, $v) => "{$k}×{$v}", array_keys($byRule), $byRule));
    printf("%-20s %-9s %7d %9d %8.1f  %s\n", $name, $commit, $files, $count, $seconds, $rules);
}
