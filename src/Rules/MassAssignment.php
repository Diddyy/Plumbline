<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Plumbline\Analysis\Ast;
use Plumbline\Analysis\Evaluator;
use Plumbline\Analysis\FunctionContext;
use Plumbline\Analysis\Scope;
use Plumbline\Analysis\Types;
use Plumbline\Severity;

/**
 * The whole, unfiltered request ($request->all(), ->except(), ->input()) is written to a model, and
 * something makes that dangerous:
 *
 *  - the model is unguarded ($guarded = [] or Model::unguard()), or
 *  - forceFill()/forceCreate() bypass the guard on purpose, or
 *  - the write goes through the query builder (Post::where(...)->update()), which ignores $fillable, or
 *  - $fillable contains attributes a user must never set (is_admin, role, user_id, balance...).
 *
 * A model with a reasonable $fillable written from $request->all() is not reported.
 */
final class MassAssignment implements TaintRule
{
    private const WRITE_METHODS = ['create', 'forcecreate', 'update', 'fill', 'forcefill', 'make', 'firstorcreate', 'updateorcreate', 'firstornew', 'insert', 'upsert', 'createquietly', 'updatequietly', 'forcefillquietly'];

    /** For these, the second argument also carries attributes. */
    private const TWO_ARG_METHODS = ['firstorcreate', 'updateorcreate', 'firstornew'];

    public function meta(): RuleMeta
    {
        return new RuleMeta(
            'MASS-001',
            'mass-assignment',
            'Unfiltered request data written to a model',
            Severity::High,
            'All request fields are written to the database, so a user can set columns the form never offered.',
            'CWE-915',
        );
    }

    public function inspect(Node $node, Scope $scope, FunctionContext $context): iterable
    {
        if ($node instanceof Expr\New_) {
            yield from $this->checkNew($node, $scope, $context);

            return;
        }
        if (! $node instanceof Expr\MethodCall && ! $node instanceof Expr\StaticCall && ! $node instanceof Expr\NullsafeMethodCall) {
            return;
        }
        $method = Ast::callName($node);
        if ($method === null || ! in_array($method, self::WRITE_METHODS, true)) {
            return;
        }

        $evaluator = new Evaluator($scope, $context);
        $data = null;
        $value = null;
        $positions = in_array($method, self::TWO_ARG_METHODS, true) ? [0, 1] : [0];
        foreach ($positions as $position) {
            $candidate = Ast::arg($node, $position);
            $candidateValue = $evaluator->evaluate($candidate);
            if ($candidateValue->bag && ! $candidateValue->validated) {
                $data = $candidate;
                $value = $candidateValue;
                break;
            }
        }
        if ($data === null || $value === null) {
            return;
        }

        $types = new Types($scope, $context);
        $models = $context->project->models();
        $receiver = $node instanceof Expr\StaticCall ? $node : $node->var;
        $model = $types->classOf($receiver);
        $isModel = $model !== null && $models->isModel($model);
        $label = $this->label($node, $model);

        // Validator::make($request->all(), ...), Cache::update(...): static calls must be on a model.
        if ($node instanceof Expr\StaticCall && ! $isModel) {
            return;
        }

        $reason = null;
        if (in_array($method, ['forcefill', 'forcecreate', 'forcefillquietly'], true)) {
            $reason = "{$method}() ignores \$fillable and \$guarded";
        } elseif (! $node instanceof Expr\StaticCall && in_array($method, ['update', 'insert', 'upsert'], true) && $types->isBuilderChain($node->var)) {
            $reason = 'a query-builder '.$method.'() ignores $fillable entirely';
        } elseif ($models->globallyUnguarded() && ($isModel || $this->isRelationOnModel($receiver, $types, $context))) {
            $reason = 'Model::unguard() is called at '.$models->unguardLocation();
        } elseif ($isModel && $models->isUnguarded($model)) {
            $reason = Ast::shortName($model).' has $guarded = []';
        } elseif ($isModel && ($sensitive = $models->sensitiveFillable($model)) !== []) {
            $reason = Ast::shortName($model).' lists '.implode(', ', $sensitive).' in $fillable';
        }

        if ($reason === null) {
            return;
        }

        yield $context->finding(
            $this->meta(),
            $node,
            "{$label} receives every request field ({$value->source}) and {$reason}. Use \$request->validated() or \$request->only([...]).",
        );
    }

    /** @return iterable<\Plumbline\Finding> */
    private function checkNew(Expr\New_ $node, Scope $scope, FunctionContext $context): iterable
    {
        $model = Ast::className($node);
        $models = $context->project->models();
        if ($model === null || ! $models->isModel($model)) {
            return;
        }
        $value = (new Evaluator($scope, $context))->evaluate(Ast::arg($node, 0));
        if (! $value->bag || $value->validated) {
            return;
        }

        $reason = match (true) {
            $models->globallyUnguarded() => 'Model::unguard() is called at '.$models->unguardLocation(),
            $models->isUnguarded($model) => Ast::shortName($model).' has $guarded = []',
            $models->sensitiveFillable($model) !== [] => Ast::shortName($model).' lists '.implode(', ', $models->sensitiveFillable($model)).' in $fillable',
            default => null,
        };
        if ($reason !== null) {
            yield $context->finding($this->meta(), $node, 'new '.Ast::shortName($model)."() receives every request field ({$value->source}) and {$reason}. Use \$request->validated() or \$request->only([...]).");
        }
    }

    /** $user->posts()->create(...) — the receiver is a relation call on a known model. */
    private function isRelationOnModel(Expr $receiver, Types $types, FunctionContext $context): bool
    {
        if (! $receiver instanceof Expr\MethodCall && ! $receiver instanceof Expr\NullsafeMethodCall) {
            return false;
        }
        $owner = $types->classOf($receiver->var);

        return $owner !== null && $context->project->models()->isModel($owner);
    }

    private function label(Node $node, ?string $model): string
    {
        $method = $node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall || $node instanceof Expr\NullsafeMethodCall
            ? ($node->name instanceof Node\Identifier ? $node->name->toString() : 'write')
            : 'write';

        return ($model !== null ? Ast::shortName($model).'::' : '').$method.'()';
    }
}
