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

final class UnsafeDeserialization implements TaintRule
{
    public function meta(): RuleMeta
    {
        return new RuleMeta(
            'DESER-001',
            'unsafe-deserialization',
            'User input is unserialized',
            Severity::High,
            'unserialize() on request data lets an attacker instantiate arbitrary classes (PHP object injection).',
            'CWE-502',
        );
    }

    public function inspect(Node $node, Scope $scope, FunctionContext $context): iterable
    {
        if (! $node instanceof Expr\FuncCall || Ast::callName($node) !== 'unserialize') {
            return;
        }
        if ($this->restrictsClasses(Ast::arg($node, 1, 'options'))) {
            return;
        }

        $value = (new Evaluator($scope, $context))->evaluate(Ast::arg($node, 0, 'data'));
        if ($value->tainted) {
            yield $context->finding($this->meta(), $node, "User input from {$value->source} is passed to unserialize(). Use json_decode(), or at least unserialize(\$data, ['allowed_classes' => false]).");
        }
    }

    private function restrictsClasses(?Expr $options): bool
    {
        if (! $options instanceof Expr\Array_) {
            return false;
        }
        foreach ($options->items as $item) {
            if ($item !== null && Ast::stringValue($item->key) === 'allowed_classes') {
                // false, or an explicit allowlist array, are both restrictions; `true` is not.
                return ! ($item->value instanceof Expr\ConstFetch && strtolower($item->value->name->toString()) === 'true');
            }
        }

        return false;
    }
}
