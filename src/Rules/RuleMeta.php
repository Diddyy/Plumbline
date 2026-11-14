<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use Plumbline\Severity;

final readonly class RuleMeta
{
    public const DOCS_BASE = 'https://github.com/Diddyy/Plumbline/blob/main/docs/rules/';

    public function __construct(
        public string $id,
        /** kebab-case short name, e.g. "sql-injection". */
        public string $name,
        public string $title,
        public Severity $severity,
        public string $summary,
        /** e.g. "CWE-89" */
        public string $cwe,
    ) {
    }

    public function helpUri(): string
    {
        return self::DOCS_BASE.$this->id.'.md';
    }
}
