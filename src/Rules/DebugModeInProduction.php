<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Plumbline\Analysis\Ast;
use Plumbline\Finding;
use Plumbline\Project\Project;
use Plumbline\Severity;

/**
 * APP_DEBUG=true in production shows stack traces, environment variables and (with Ignition)
 * sometimes worse to anyone who can trigger an error.
 */
final class DebugModeInProduction implements ProjectRule
{
    public function meta(): RuleMeta
    {
        return new RuleMeta(
            'CFG-001',
            'debug-mode-in-production',
            'Debug mode enabled for production',
            Severity::High,
            'Debug mode exposes stack traces, configuration and secrets to visitors.',
            'CWE-489',
        );
    }

    public function check(Project $project): iterable
    {
        foreach ($project->envFiles() as $file => $contents) {
            if (preg_match('/\.(example|sample|dist|testing|local|dusk)/i', $file)) {
                continue;
            }
            $vars = $this->parseEnv($contents);
            $isProductionFile = (bool) preg_match('/^\.env\.(prod|production|live)/i', $file);
            $isStagingFile = (bool) preg_match('/^\.env\.(staging|stage|uat)/i', $file);
            $declaresProduction = strtolower($vars['APP_ENV']['value'] ?? '') === 'production';

            if (! isset($vars['APP_DEBUG']) || ! in_array(strtolower($vars['APP_DEBUG']['value']), ['true', '1', 'on', 'yes'], true)) {
                continue;
            }
            $line = $vars['APP_DEBUG']['line'];

            if ($isProductionFile || $declaresProduction) {
                yield new Finding($this->meta()->id, Severity::High, "{$file} sets APP_DEBUG=true for production. Set APP_DEBUG=false.", $file, $line, 'APP_DEBUG='.$vars['APP_DEBUG']['value']);
            } elseif ($isStagingFile) {
                yield new Finding($this->meta()->id, Severity::Medium, "{$file} sets APP_DEBUG=true. Staging servers are often reachable from the internet; prefer APP_DEBUG=false.", $file, $line, 'APP_DEBUG='.$vars['APP_DEBUG']['value']);
            }
        }

        yield from $this->checkConfig($project);
    }

    /**
     * config/app.php: 'debug' => true, or env('APP_DEBUG', true)
     *
     * @return iterable<Finding>
     */
    private function checkConfig(Project $project): iterable
    {
        $config = $project->file('config/app.php');
        if ($config === null) {
            return;
        }
        foreach (Ast::find($config->stmts(), fn (Node $n) => $n instanceof Node\ArrayItem && Ast::stringValue($n->key) === 'debug') as $item) {
            /** @var Node\ArrayItem $item */
            $value = $item->value;
            while ($value instanceof Expr\Cast) {
                $value = $value->expr;
            }
            $line = $item->getStartLine();
            if ($this->isTrue($value)) {
                yield new Finding($this->meta()->id, Severity::High, "config/app.php hard-codes 'debug' => true, so debug mode is on in every environment. Use (bool) env('APP_DEBUG', false).", 'config/app.php', $line, $config->line($line));
            } elseif ($value instanceof Expr\FuncCall && Ast::callName($value) === 'env' && $this->isTrue(Ast::arg($value, 1))) {
                yield new Finding($this->meta()->id, Severity::Medium, "config/app.php defaults 'debug' to true when APP_DEBUG is missing, so a server without that variable runs in debug mode. Use env('APP_DEBUG', false).", 'config/app.php', $line, $config->line($line));
            }
        }
    }

    private function isTrue(?Node $node): bool
    {
        return $node instanceof Expr\ConstFetch && strtolower($node->name->toString()) === 'true';
    }

    /** @return array<string, array{value: string, line: int}> */
    private function parseEnv(string $contents): array
    {
        $out = [];
        foreach (preg_split('/\R/', $contents) ?: [] as $i => $line) {
            if (preg_match('/^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*?)\s*$/', $line, $m)) {
                $value = trim(preg_replace('/\s+#.*$/', '', $m[2]) ?? $m[2], " \t\"'");
                $out[$m[1]] = ['value' => $value, 'line' => $i + 1];
            }
        }

        return $out;
    }
}
