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

final class SqlInjection implements TaintRule
{
    /** Query builder / Eloquent methods whose first argument is raw SQL. */
    private const RAW_METHODS = [
        'whereraw', 'orwhereraw', 'havingraw', 'orhavingraw', 'orderbyraw', 'groupbyraw', 'selectraw', 'fromraw',
        'wherenotraw', 'orwherenotraw', 'joinraw',
    ];

    /** DB facade / connection methods whose first argument is a full SQL statement. */
    private const STATEMENT_METHODS = [
        'raw', 'select', 'selectone', 'selectresultsets', 'scalar', 'statement', 'unprepared', 'insert', 'update',
        'delete', 'affectingstatement', 'cursor',
    ];

    public function meta(): RuleMeta
    {
        return new RuleMeta(
            'SQLI-001',
            'sql-injection',
            'User input reaches raw SQL',
            Severity::Critical,
            'Request data is concatenated or interpolated into a raw SQL string instead of being passed as a binding.',
            'CWE-89',
        );
    }

    public function inspect(Node $node, Scope $scope, FunctionContext $context): iterable
    {
        $sink = $this->sink($node);
        if ($sink === null) {
            return;
        }
        [$sql, $label] = $sink;

        $value = (new Evaluator($scope, $context))->evaluate($sql);
        if (! $value->tainted) {
            return;
        }

        yield $context->finding(
            $this->meta(),
            $node,
            "User input from {$value->source} reaches raw SQL in {$label}. Pass it as a binding instead, e.g. {$this->hint($label)}.",
        );
    }

    /** @return array{0: Expr, 1: string}|null */
    private function sink(Node $node): ?array
    {
        if ($node instanceof Expr\New_ && in_array(Ast::className($node), ['Illuminate\\Database\\Query\\Expression', 'Expression'], true)) {
            $arg = Ast::arg($node, 0);

            return $arg !== null ? [$arg, 'new Expression()'] : null;
        }

        if (! $node instanceof Expr\MethodCall && ! $node instanceof Expr\StaticCall && ! $node instanceof Expr\NullsafeMethodCall) {
            return null;
        }
        $method = Ast::callName($node);
        $arg = Ast::arg($node, 0);
        if ($method === null || $arg === null) {
            return null;
        }

        // ->whereRaw($sql), Post::whereRaw($sql)
        if (in_array($method, self::RAW_METHODS, true)) {
            return [$arg, $method.'()'];
        }

        // DB::select($sql), DB::raw($sql)
        if ($node instanceof Expr\StaticCall && Ast::isFacade($node, 'DB') && in_array($method, self::STATEMENT_METHODS, true)) {
            return [$arg, 'DB::'.$method.'()'];
        }

        // DB::connection('x')->select($sql)
        if ($node instanceof Expr\MethodCall && in_array($method, self::STATEMENT_METHODS, true)
            && $node->var instanceof Expr\StaticCall && Ast::isFacade($node->var, 'DB') && Ast::callName($node->var) === 'connection') {
            return [$arg, 'DB::connection()->'.$method.'()'];
        }

        // DB::getPdo()->query($sql) / ->exec($sql)
        if ($node instanceof Expr\MethodCall && in_array($method, ['query', 'exec', 'prepare'], true)
            && ($node->var instanceof Expr\MethodCall || $node->var instanceof Expr\StaticCall)
            && in_array(Ast::callName($node->var), ['getpdo', 'getreadpdo'], true)) {
            return [$arg, 'PDO::'.$method.'()'];
        }

        return null;
    }

    private function hint(string $label): string
    {
        return str_starts_with($label, 'DB::') || str_starts_with($label, 'PDO')
            ? "DB::select('... where id = ?', [\$id])"
            : "->whereRaw('lower(name) = ?', [\$name])";
    }
}
