<?php

declare(strict_types=1);

namespace Plumbline;

use Plumbline\Analysis\TaintEngine;
use Plumbline\Project\Project;
use Plumbline\Rules\ProjectRule;
use Plumbline\Rules\Rule;
use Plumbline\Rules\TaintRule;
use Plumbline\Suppression\Baseline;
use Plumbline\Suppression\InlineSuppressor;

final class Scanner
{
    /** @param list<Rule> $rules */
    public function __construct(private readonly array $rules)
    {
    }

    public function scan(Project $project, ?Baseline $baseline = null): ScanResult
    {
        $raw = [];
        $taintRules = [];
        foreach ($this->rules as $rule) {
            if ($rule instanceof TaintRule) {
                $taintRules[] = $rule;
            }
            if ($rule instanceof ProjectRule) {
                foreach ($rule->check($project) as $finding) {
                    $raw[] = $finding;
                }
            }
        }
        foreach ((new TaintEngine($project, $taintRules))->run() as $finding) {
            $raw[] = $finding;
        }

        $suppressor = new InlineSuppressor($project);
        $findings = [];
        $seen = [];
        $suppressed = 0;
        $baselined = 0;
        foreach ($raw as $finding) {
            $key = $finding->ruleId.'|'.$finding->file.'|'.$finding->line;
            if (isset($seen[$key])) {
                continue; // one finding per rule per line is enough
            }
            $seen[$key] = true;

            if ($suppressor->isSuppressed($finding)) {
                $suppressed++;
            } elseif ($baseline?->contains($finding)) {
                $baselined++;
            } else {
                $findings[] = $finding;
            }
        }

        usort($findings, fn (Finding $a, Finding $b) => [$a->file, $a->line, $a->ruleId] <=> [$b->file, $b->line, $b->ruleId]);

        $parseErrors = [];
        foreach ($project->phpFiles() as $file) {
            if ($file->parseError() !== null) {
                $parseErrors[$file->relativePath] = (string) $file->parseError();
            }
        }

        return new ScanResult($findings, $suppressed, $baselined, $parseErrors, count($project->phpFiles()) + count($project->bladeFiles()));
    }

    /** @return list<Rule> */
    public function rules(): array
    {
        return $this->rules;
    }
}
