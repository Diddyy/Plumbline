<?php

declare(strict_types=1);

namespace Plumbline\Console;

use Plumbline\Plumbline;
use Plumbline\Project\Project;
use Plumbline\Report\ConsoleReporter;
use Plumbline\Report\GithubReporter;
use Plumbline\Report\JsonReporter;
use Plumbline\Report\Reporter;
use Plumbline\Report\SarifReporter;
use Plumbline\Rules\Rule;
use Plumbline\Scanner;
use Plumbline\Severity;
use Plumbline\Suppression\Baseline;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'scan', description: 'Scan a Laravel project for security issues')]
final class ScanCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addArgument('path', InputArgument::OPTIONAL, 'Project root to scan', '.')
            ->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'console, json, sarif or github', 'console')
            ->addOption('output', 'o', InputOption::VALUE_REQUIRED, 'Write the report to a file instead of stdout')
            ->addOption('baseline', 'b', InputOption::VALUE_REQUIRED, 'Ignore findings recorded in this baseline file')
            ->addOption('generate-baseline', null, InputOption::VALUE_REQUIRED, 'Write all current findings to a baseline file and exit 0')
            ->addOption('min-severity', null, InputOption::VALUE_REQUIRED, 'Only report findings at or above: low, medium, high, critical', 'low')
            ->addOption('fail-on', null, InputOption::VALUE_REQUIRED, 'Exit 1 when a finding at or above this severity remains (or "none")', 'low')
            ->addOption('exclude', 'e', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Extra directories to skip (relative to the root)')
            ->addOption('rules', 'r', InputOption::VALUE_REQUIRED, 'Comma-separated rule IDs to run (default: all)')
            ->addOption('skip-rules', null, InputOption::VALUE_REQUIRED, 'Comma-separated rule IDs to skip');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $root = realpath((string) $input->getArgument('path'));
        if ($root === false || ! is_dir($root)) {
            $output->writeln('<error>Path not found: '.$input->getArgument('path').'</error>');

            return 2;
        }

        $minimum = Severity::tryFrom((string) $input->getOption('min-severity'));
        $failOnOption = (string) $input->getOption('fail-on');
        $failOn = $failOnOption === 'none' ? null : Severity::tryFrom($failOnOption);
        if ($minimum === null || ($failOn === null && $failOnOption !== 'none')) {
            $output->writeln('<error>Severities are: low, medium, high, critical (fail-on also accepts none).</error>');

            return 2;
        }

        $reporter = $this->reporter((string) $input->getOption('format'));
        if ($reporter === null) {
            $output->writeln('<error>Unknown format. Use console, json, sarif or github.</error>');

            return 2;
        }

        $rules = $this->selectRules($input->getOption('rules'), $input->getOption('skip-rules'));
        /** @var list<string> $extraExcludes */
        $extraExcludes = $input->getOption('exclude');
        $project = new Project($root, array_merge(Project::DEFAULT_EXCLUDES, $extraExcludes));
        // stderr, so --format=sarif/json output stays valid.
        $stderr = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
        foreach ($project->skippedEmbeddedApps() as $embedded) {
            $stderr->writeln("<comment>Skipped {$embedded}/: it has its own vendor/autoload.php, so it looks like a separately installed application.</comment>");
        }
        if (! $project->looksLikeLaravel()) {
            $stderr->writeln('<comment>Warning: '.$root.' does not look like a Laravel project (no artisan file or laravel/* dependency). Plumbline\'s rules are Laravel-specific.</comment>');
        }

        $baselinePath = $input->getOption('baseline');
        $baseline = is_string($baselinePath) ? Baseline::load($baselinePath) : null;

        $scanner = new Scanner($rules);
        $result = $scanner->scan($project, $baseline)->filter($minimum);

        $generate = $input->getOption('generate-baseline');
        if (is_string($generate)) {
            Baseline::write($generate, $result->findings);
            $output->writeln('Wrote '.count($result->findings).' finding(s) to '.$generate);

            return 0;
        }

        $report = $reporter->render($result, $rules);
        $target = $input->getOption('output');
        if (is_string($target)) {
            file_put_contents($target, $reporter instanceof ConsoleReporter ? strip_tags($report) : $report);
            $output->writeln('Report written to '.$target);
        } elseif ($reporter instanceof ConsoleReporter) {
            $output->write($report);
        } else {
            $output->write($report, false, OutputInterface::OUTPUT_RAW);
        }

        return $failOn !== null && $result->hasFindingsAtLeast($failOn) ? 1 : 0;
    }

    private function reporter(string $format): ?Reporter
    {
        return match ($format) {
            'console', 'text' => new ConsoleReporter(),
            'json' => new JsonReporter(),
            'sarif' => new SarifReporter(),
            'github' => new GithubReporter(),
            default => null,
        };
    }

    /** @return list<Rule> */
    private function selectRules(mixed $only, mixed $skip): array
    {
        $ids = fn (mixed $value) => is_string($value) && $value !== '' ? array_map(fn ($s) => strtoupper(trim($s)), explode(',', $value)) : [];
        $onlyIds = $ids($only);
        $skipIds = $ids($skip);

        return array_values(array_filter(
            Plumbline::defaultRules(),
            fn (Rule $rule) => ($onlyIds === [] || in_array($rule->meta()->id, $onlyIds, true)) && ! in_array($rule->meta()->id, $skipIds, true),
        ));
    }
}
