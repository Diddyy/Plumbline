<?php

declare(strict_types=1);

namespace Plumbline\Report;

use Plumbline\Rules\Rule;
use Plumbline\ScanResult;

interface Reporter
{
    /** @param list<Rule> $rules */
    public function render(ScanResult $result, array $rules): string;
}
