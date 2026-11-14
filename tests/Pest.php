<?php

declare(strict_types=1);

use Plumbline\Finding;
use Plumbline\Plumbline;
use Plumbline\Project\Project;
use Plumbline\Scanner;

/**
 * Run the scanner on a fixture directory, optionally limited to one rule.
 *
 * @return list<Finding>
 */
function scanFixture(string $dir, ?string $ruleId = null): array
{
    $rules = array_values(array_filter(
        Plumbline::defaultRules(),
        fn ($rule) => $ruleId === null || $rule->meta()->id === $ruleId,
    ));

    return (new Scanner($rules))->scan(new Project($dir, ['vendor', 'node_modules']))->findings;
}

/**
 * Lines marked "expect: RULE-ID" in any file of a fixture directory.
 *
 * @return list<string> "RULE-ID file:line"
 */
function expectedMarkers(string $dir, ?string $ruleId = null): array
{
    $out = [];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $file) {
        /** @var SplFileInfo $file */
        $relative = str_replace('\\', '/', substr($file->getPathname(), strlen($dir) + 1));
        foreach (preg_split('/\R/', (string) file_get_contents($file->getPathname())) ?: [] as $i => $line) {
            if (preg_match_all('/expect:\s*([A-Z]+-\d{3})/', $line, $matches)) {
                foreach ($matches[1] as $id) {
                    if ($ruleId === null || $id === $ruleId) {
                        $out[] = "{$id} {$relative}:".($i + 1);
                    }
                }
            }
        }
    }
    sort($out);

    return $out;
}

/** @param list<Finding> $findings @return list<string> */
function findingKeys(array $findings): array
{
    $keys = array_map(fn (Finding $f) => "{$f->ruleId} {$f->file}:{$f->line}", $findings);
    sort($keys);

    return $keys;
}

/** @param array<string, string> $files relative path => contents */
function tempApp(array $files): string
{
    $dir = sys_get_temp_dir().DIRECTORY_SEPARATOR.'plumbline-'.bin2hex(random_bytes(4));
    foreach ($files as $path => $contents) {
        $full = $dir.DIRECTORY_SEPARATOR.str_replace('/', DIRECTORY_SEPARATOR, $path);
        is_dir(dirname($full)) || mkdir(dirname($full), 0777, true);
        file_put_contents($full, $contents);
    }

    return $dir;
}

function fixturePath(string ...$parts): string
{
    return __DIR__.DIRECTORY_SEPARATOR.'Fixtures'.DIRECTORY_SEPARATOR.implode(DIRECTORY_SEPARATOR, $parts);
}
