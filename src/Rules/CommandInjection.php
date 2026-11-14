<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Plumbline\Analysis\Ast;
use Plumbline\Analysis\Evaluator;
use Plumbline\Analysis\FunctionContext;
use Plumbline\Analysis\Scope;
use Plumbline\Severity;

final class CommandInjection implements TaintRule
{
    private const SHELL_FUNCTIONS = ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'pcntl_exec'];

    public function meta(): RuleMeta
    {
        return new RuleMeta(
            'CMD-001',
            'command-injection',
            'User input reaches a shell command',
            Severity::Critical,
            'Request data is built into a command string that is run through a shell.',
            'CWE-78',
        );
    }

    public function inspect(Node $node, Scope $scope, FunctionContext $context): iterable
    {
        $evaluator = new Evaluator($scope, $context);

        if ($node instanceof Expr\ShellExec) {
            $parts = array_filter($node->parts, fn ($p) => ! $p instanceof Node\InterpolatedStringPart);
            foreach ($parts as $part) {
                $value = $evaluator->evaluate($part);
                if ($value->tainted) {
                    yield $context->finding($this->meta(), $node, "User input from {$value->source} is interpolated into a backtick shell command. Use Process::run([...]) with an argument array.");

                    return;
                }
            }

            return;
        }

        $label = null;
        if ($node instanceof Expr\FuncCall && in_array(Ast::callName($node), self::SHELL_FUNCTIONS, true)) {
            $label = Ast::callName($node).'()';
        } elseif ($node instanceof Expr\StaticCall && (Ast::isFacade($node, 'Process') || Ast::className($node) === 'Symfony\\Component\\Process\\Process')
            && in_array(Ast::callName($node), ['run', 'start', 'command', 'fromshellcommandline', 'pipe', 'concurrently'], true)) {
            $label = 'Process::'.Ast::callName($node).'()';
        }
        if ($label === null) {
            return;
        }

        $command = Ast::arg($node, 0, 'command');
        // An argument array is passed to the OS without a shell: that's the safe form.
        if ($command === null || $command instanceof Expr\Array_) {
            return;
        }

        $value = $evaluator->evaluate($command);
        if ($value->tainted) {
            yield $context->finding($this->meta(), $node, "User input from {$value->source} reaches {$label}, which runs through a shell. Pass an argument array (Process::run(['convert', \$path])) or escape with escapeshellarg().");
        }
    }
}
