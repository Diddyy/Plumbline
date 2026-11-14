<?php

declare(strict_types=1);

namespace Plumbline\Suppression;

use Plumbline\Finding;
use RuntimeException;

/**
 * A baseline records existing findings so CI only fails on new ones. Entries are matched by
 * fingerprint (rule + file + normalised source line), so unrelated edits don't invalidate them.
 */
final class Baseline
{
    /** @param array<string, true> $fingerprints */
    private function __construct(private readonly array $fingerprints)
    {
    }

    public static function load(string $path): self
    {
        if (! is_file($path)) {
            throw new RuntimeException("Baseline file not found: {$path}");
        }
        $data = json_decode((string) file_get_contents($path), true);
        if (! is_array($data) || ! isset($data['findings']) || ! is_array($data['findings'])) {
            throw new RuntimeException("Baseline file is not valid: {$path}");
        }
        $fingerprints = [];
        foreach ($data['findings'] as $entry) {
            if (is_array($entry) && isset($entry['fingerprint']) && is_string($entry['fingerprint'])) {
                $fingerprints[$entry['fingerprint']] = true;
            }
        }

        return new self($fingerprints);
    }

    public function contains(Finding $finding): bool
    {
        return isset($this->fingerprints[$finding->fingerprint()]);
    }

    /** @param list<Finding> $findings */
    public static function write(string $path, array $findings): void
    {
        $entries = array_map(fn (Finding $f) => [
            'rule' => $f->ruleId,
            'file' => $f->file,
            'fingerprint' => $f->fingerprint(),
            'message' => $f->message,
        ], $findings);

        file_put_contents($path, json_encode(['version' => 1, 'findings' => $entries], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n");
    }
}
