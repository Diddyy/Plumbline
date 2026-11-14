<?php

declare(strict_types=1);

namespace Plumbline\Report;

use Plumbline\ScanResult;
use Plumbline\Severity;

/** GitHub Actions workflow commands: findings show up as annotations on the PR diff. */
final class GithubReporter implements Reporter
{
    public function render(ScanResult $result, array $rules): string
    {
        $out = '';
        foreach ($result->findings as $finding) {
            $command = match ($finding->severity) {
                Severity::Critical, Severity::High => 'error',
                Severity::Medium => 'warning',
                Severity::Low => 'notice',
            };
            $out .= sprintf(
                "::%s file=%s,line=%d,title=%s::%s\n",
                $command,
                $this->property($finding->file),
                $finding->line,
                $this->property('Plumbline '.$finding->ruleId),
                $this->data($finding->message),
            );
        }

        return $out;
    }

    private function data(string $value): string
    {
        return str_replace(['%', "\r", "\n"], ['%25', '%0D', '%0A'], $value);
    }

    private function property(string $value): string
    {
        return str_replace([':', ','], ['%3A', '%2C'], $this->data($value));
    }
}
