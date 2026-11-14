<?php

declare(strict_types=1);

namespace Plumbline\Report;

use Plumbline\Plumbline;
use Plumbline\ScanResult;
use Plumbline\Severity;
use Symfony\Component\Console\Formatter\OutputFormatter;

/** Human-readable output, grouped by file. Uses Symfony console tags, so colour degrades gracefully. */
final class ConsoleReporter implements Reporter
{
    public function render(ScanResult $result, array $rules): string
    {
        $out = "\n <options=bold>Plumbline</> ".Plumbline::VERSION." — {$result->filesScanned} files scanned\n\n";

        $currentFile = null;
        foreach ($result->findings as $finding) {
            if ($finding->file !== $currentFile) {
                $currentFile = $finding->file;
                $out .= ' <options=bold;underscore>'.OutputFormatter::escape($finding->file)."</>\n";
            }
            $out .= sprintf(
                "  %s <fg=gray>%s</> line %d\n     %s\n",
                $this->badge($finding->severity),
                $finding->ruleId,
                $finding->line,
                OutputFormatter::escape($finding->message),
            );
            if ($finding->snippet !== '') {
                $out .= '     <fg=gray>│ '.OutputFormatter::escape(mb_strimwidth($finding->snippet, 0, 140, '…'))."</>\n";
            }
            $out .= "\n";
        }

        $counts = array_filter($result->countsBySeverity());
        if ($result->findings === []) {
            $out .= " <fg=green;options=bold>No findings.</>\n";
        } else {
            $parts = [];
            foreach ($counts as $severity => $count) {
                $parts[] = $count.' '.$severity;
            }
            $out .= ' <options=bold>'.count($result->findings).' finding'.(count($result->findings) === 1 ? '' : 's').'</> ('.implode(', ', $parts).")\n";
        }
        if ($result->suppressed > 0 || $result->baselined > 0) {
            $out .= " <fg=gray>{$result->suppressed} suppressed inline, {$result->baselined} in baseline</>\n";
        }
        foreach ($result->parseErrors as $file => $error) {
            $out .= ' <fg=yellow>Could not parse '.OutputFormatter::escape($file).': '.OutputFormatter::escape($error)."</>\n";
        }

        return $out."\n";
    }

    private function badge(Severity $severity): string
    {
        return match ($severity) {
            Severity::Critical => '<fg=white;bg=red;options=bold> CRITICAL </>',
            Severity::High => '<fg=red;options=bold>HIGH    </>',
            Severity::Medium => '<fg=yellow;options=bold>MEDIUM  </>',
            Severity::Low => '<fg=cyan>LOW     </>',
        };
    }
}
