<?php

declare(strict_types=1);

namespace Plumbline\Report;

use Plumbline\Finding;
use Plumbline\Plumbline;
use Plumbline\ScanResult;

final class JsonReporter implements Reporter
{
    public function render(ScanResult $result, array $rules): string
    {
        return json_encode([
            'tool' => 'plumbline',
            'version' => Plumbline::VERSION,
            'summary' => [
                'files' => $result->filesScanned,
                'findings' => count($result->findings),
                'by_severity' => $result->countsBySeverity(),
                'suppressed' => $result->suppressed,
                'baselined' => $result->baselined,
            ],
            'findings' => array_map(fn (Finding $f) => $f->toArray(), $result->findings),
            'parse_errors' => $result->parseErrors,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n";
    }
}
