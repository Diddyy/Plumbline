<?php

declare(strict_types=1);

namespace Plumbline\Suppression;

use Plumbline\Finding;
use Plumbline\Project\Project;

/**
 * Inline suppressions, on the finding's line or the line above:
 *
 *     // plumbline-ignore SQLI-001: column comes from a hard-coded allowlist above
 *     {{-- plumbline-ignore XSS-001: sanitised with HTMLPurifier in the model --}}
 *     # plumbline-ignore CFG-001: this file is for the internal demo box
 *
 * A reason after the colon is required, so suppressions stay reviewable.
 */
final class InlineSuppressor
{
    private const PATTERN = '/plumbline-ignore\s+((?:[A-Z]+-\d{3}\s*,\s*)*[A-Z]+-\d{3})\s*:\s*\S/';

    /** @var array<string, list<string>> */
    private array $lines = [];

    public function __construct(private readonly Project $project)
    {
    }

    public function isSuppressed(Finding $finding): bool
    {
        $lines = $this->lines($finding->file);
        foreach ([$finding->line, $finding->line - 1] as $number) {
            $text = $lines[$number - 1] ?? '';
            if (! str_contains($text, 'plumbline-ignore') || ! preg_match(self::PATTERN, $text, $m)) {
                continue;
            }
            $ids = array_map('trim', explode(',', $m[1]));
            if (in_array($finding->ruleId, $ids, true)) {
                return true;
            }
        }

        return false;
    }

    /** @return list<string> */
    private function lines(string $file): array
    {
        if (! isset($this->lines[$file])) {
            $path = $this->project->root.DIRECTORY_SEPARATOR.$file;
            $contents = is_file($path) ? (string) file_get_contents($path) : '';
            $this->lines[$file] = preg_split('/\R/', $contents) ?: [];
        }

        return $this->lines[$file];
    }
}
