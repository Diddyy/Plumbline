<?php

declare(strict_types=1);

namespace Plumbline\Analysis;

use PhpParser\Node\Expr;

/** Best-effort class resolution for expressions, enough to know which Eloquent model is being written. */
final class Types
{
    private const SINGLE_MODEL_METHODS = [
        'find', 'findorfail', 'findornew', 'first', 'firstorfail', 'firstornew', 'firstwhere', 'sole', 'make',
        'create', 'firstorcreate', 'updateorcreate', 'findorcreate', 'fresh', 'replicate',
    ];

    public function __construct(private readonly Scope $scope, private readonly FunctionContext $context)
    {
    }

    public function classOf(?Expr $expr): ?string
    {
        if ($expr instanceof Expr\Variable && is_string($expr->name)) {
            return $expr->name === 'this' ? $this->context->class?->name : $this->scope->type($expr->name);
        }
        if ($expr instanceof Expr\New_ || $expr instanceof Expr\StaticCall) {
            $class = Ast::className($expr);
            if ($class !== null && in_array(strtolower($class), ['static', 'self'], true)) {
                return $this->context->class?->name;
            }
            if ($expr instanceof Expr\StaticCall && Ast::callName($expr) === 'user' && Ast::isFacade($expr, 'Auth')) {
                return $this->userModel();
            }

            return $class;
        }
        if ($expr instanceof Expr\MethodCall || $expr instanceof Expr\NullsafeMethodCall) {
            if (Ast::callName($expr) === 'user' && $this->isAuthSource($expr->var)) {
                return $this->userModel();
            }
            // Model::where(...)->firstOrFail() — the root of the chain names the model.
            $root = $this->builderRoot($expr);

            return $root !== null ? $this->classOf($root) : null;
        }

        return null;
    }

    /** True when the call chain is a query builder started from a model (Post::where(...)->...). */
    public function isBuilderChain(Expr $expr): bool
    {
        $root = $this->builderRoot($expr);
        if (! $root instanceof Expr\StaticCall) {
            return false;
        }

        // Any call in the chain that returns a single model (->first(), ::find()) makes it a model write.
        $current = $expr;
        while (true) {
            if (in_array(Ast::callName($current), self::SINGLE_MODEL_METHODS, true)) {
                return false;
            }
            if (! $current instanceof Expr\MethodCall && ! $current instanceof Expr\NullsafeMethodCall) {
                break;
            }
            $current = $current->var;
        }

        $class = $this->classOf($root);

        return ($class !== null && $this->context->project->models()->isModel($class))
            || (Ast::isFacade($root, 'DB') && Ast::callName($root) === 'table');
    }

    public function userModel(): ?string
    {
        foreach (['App\\Models\\User', 'App\\User'] as $candidate) {
            if ($this->context->project->classes()->get($candidate) !== null) {
                return $candidate;
            }
        }

        return null;
    }

    private function builderRoot(Expr $expr): ?Expr
    {
        $current = $expr;
        $guard = 0;
        while (($current instanceof Expr\MethodCall || $current instanceof Expr\NullsafeMethodCall) && $guard++ < 64) {
            $current = $current->var;
        }

        return $current instanceof Expr\StaticCall ? $current : null;
    }

    private function isAuthSource(Expr $expr): bool
    {
        if ($expr instanceof Expr\FuncCall) {
            return in_array(Ast::callName($expr), ['auth', 'request'], true);
        }
        if ($expr instanceof Expr\Variable) {
            if ($expr->name === 'this') {
                return $this->context->isFormRequest;
            }
            $value = is_string($expr->name) ? $this->scope->get($expr->name) : null;

            return $value !== null && $value->request;
        }
        if ($expr instanceof Expr\StaticCall) {
            return Ast::isFacade($expr, 'Auth') || Ast::isFacade($expr, 'Request');
        }
        if ($expr instanceof Expr\MethodCall) {
            // auth()->guard('web')->user()
            return Ast::callName($expr) === 'guard' && $this->isAuthSource($expr->var);
        }

        return false;
    }
}
