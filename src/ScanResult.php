<?php

declare(strict_types=1);

namespace Plumbline;

final readonly class ScanResult
{
    public function __construct(
        /** @var list<Finding> */
        public array $findings,
        public int $suppressed,
        public int $baselined,
        /** @var array<string, string> file => parse error */
        public array $parseErrors,
        public int $filesScanned,
    ) {
    }

    public function filter(Severity $minimum): self
    {
        return new self(
            array_values(array_filter($this->findings, fn (Finding $f) => $f->severity->atLeast($minimum))),
            $this->suppressed,
            $this->baselined,
            $this->parseErrors,
            $this->filesScanned,
        );
    }

    public function hasFindingsAtLeast(Severity $severity): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->severity->atLeast($severity)) {
                return true;
            }
        }

        return false;
    }

    /** @return array<string, int> severity => count */
    public function countsBySeverity(): array
    {
        $counts = [];
        foreach (Severity::cases() as $severity) {
            $counts[$severity->value] = 0;
        }
        foreach ($this->findings as $finding) {
            $counts[$finding->severity->value]++;
        }

        return $counts;
    }
}
