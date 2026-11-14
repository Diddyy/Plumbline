<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use Plumbline\Analysis\Ast;
use Plumbline\Analysis\FunctionContext;
use Plumbline\Analysis\RouteAction;
use Plumbline\Finding;
use Plumbline\Project\ClassInfo;
use Plumbline\Project\Project;
use Plumbline\Severity;

/**
 * Livewire actions are public endpoints: the browser can call any public method with any arguments
 * (`$wire.delete(123)`). An action that looks up a record by a client-supplied ID and changes it,
 * without an authorization check, lets anyone with access to the page edit or delete any record.
 *
 * Stays quiet when the lookup is scoped to the current user (auth()->user()->posts()->find($id),
 * ->where('user_id', auth()->id())), when there is any authorization evidence ($this->authorize(),
 * Gate::, ->can(), abort_if/abort_unless, ownership comparisons, access-check helpers), when the record
 * comes from a #[Locked] or model-typed property, and for models with a global (tenant/team) scope.
 */
final class LivewireAuthorization implements ProjectRule
{
    private const LIFECYCLE = ['mount', 'render', 'boot', 'booted', 'hydrate', 'dehydrate', 'rendering', 'rendered', 'exception', 'placeholder', 'rules', 'messages', 'validationattributes'];

    private const MUTATORS = [
        'update', 'delete', 'forcedelete', 'save', 'restore', 'increment', 'decrement', 'touch', 'push', 'sync',
        'attach', 'detach', 'toggle', 'syncwithoutdetaching', 'updatequietly', 'deletequietly', 'savequietly', 'destroy',
    ];

    private const LOOKUPS = ['find', 'findorfail', 'findornew', 'findmany', 'where', 'wherein', 'wherekey', 'firstwhere', 'firstorfail', 'first', 'sole'];

    public function meta(): RuleMeta
    {
        return new RuleMeta(
            'AUTHZ-002',
            'livewire-missing-authorization',
            'Livewire action changes a client-chosen record without an authorization check',
            Severity::High,
            'Any visitor of the component can call the action with another record\'s ID.',
            'CWE-639',
        );
    }

    public function check(Project $project): iterable
    {
        $classes = $project->classes();
        foreach ($classes->all() as $class) {
            if (! $classes->extends($class->name, 'Livewire\\Component')) {
                continue;
            }
            foreach ($class->node->getMethods() as $method) {
                $name = strtolower($method->name->toString());
                if (! $method->isPublic() || $method->isStatic() || str_starts_with($name, '__')
                    || in_array($name, self::LIFECYCLE, true) || preg_match('/^(updating|updated|boot|hydrate|dehydrate|mount)/', $name)) {
                    continue;
                }
                yield from $this->checkAction($project, $class, $method);
            }
        }
    }

    /** @return iterable<Finding> */
    private function checkAction(Project $project, ClassInfo $class, Stmt\ClassMethod $method): iterable
    {
        $context = new FunctionContext($project, $class->file, $class, $method);
        $clientValues = $this->clientValues($method, $context);
        if ($clientValues === []) {
            return;
        }
        $action = RouteAction::forMethod($method, $class, $project);
        if ($action->hasAuthorizationEvidence()) {
            return;
        }

        // $post = Post::findOrFail($id);  ...  $post->delete();
        $chosen = [];
        foreach (Ast::find($method->stmts ?? [], fn (Node $n) => $n instanceof Expr\Assign) as $assign) {
            /** @var Expr\Assign $assign */
            $model = $this->clientChosenLookup($assign->expr, $clientValues, $project);
            $name = Ast::varName($assign->var);
            if ($name !== null && $model !== null) {
                $chosen[$name] = $model;
            }
        }

        foreach (Ast::find($method->stmts ?? [], fn (Node $n) => ($n instanceof Expr\MethodCall || $n instanceof Expr\NullsafeMethodCall || $n instanceof Expr\StaticCall)
            && in_array(Ast::callName($n), self::MUTATORS, true)) as $call) {
            /** @var Expr\MethodCall|Expr\NullsafeMethodCall|Expr\StaticCall $call */
            $model = null;
            if ($call instanceof Expr\StaticCall) {
                // Post::destroy($id)
                $class2 = Ast::className($call);
                if ($class2 !== null && $project->models()->isModel($class2) && $this->mentionsAny($call, $clientValues)) {
                    $model = $class2;
                }
            } else {
                $root = $this->chainRoot($call);
                $rootName = Ast::varName($root);
                $model = $rootName !== null ? ($chosen[$rootName] ?? null) : $this->clientChosenLookup($call->var, $clientValues, $project);
            }
            if ($model === null || $project->models()->hasGlobalScope($model)) {
                continue;
            }

            $short = (string) Ast::shortName($model);
            $verb = in_array(Ast::callName($call), ['delete', 'forcedelete', 'destroy', 'detach', 'deletequietly'], true) ? 'deletes' : 'changes';
            $line = $call->getStartLine();

            yield new Finding(
                $this->meta()->id,
                $this->meta()->severity,
                "Livewire action {$class->shortName()}::{$method->name->toString()}() {$verb} a {$short} chosen by the browser without an authorization check. Livewire actions can be called with any arguments, so anyone who can load this component can do this to any {$short}. Add \$this->authorize(...) or scope the lookup to the user (auth()->user()->...()->findOrFail(\$id)).",
                $class->file->relativePath,
                $line,
                $class->file->line($line),
            );

            return; // one finding per action is enough
        }
    }

    /**
     * Names of values the browser controls in this action: scalar/untyped parameters and
     * user-controllable public properties ("this->name").
     *
     * @return list<string>
     */
    private function clientValues(Stmt\ClassMethod $method, FunctionContext $context): array
    {
        $out = [];
        foreach ($method->getParams() as $param) {
            $name = Ast::varName($param->var);
            $types = Ast::typeNames($param->type);
            if ($name !== null && ($types === [] || array_diff($types, ['string', 'int', 'mixed', 'array']) === [])) {
                $out[] = $name;
            }
        }
        // For IDOR an int property is exactly what matters (it's the ID), so this differs from the
        // taint engine's notion: any public property the browser can set, i.e. not #[Locked] and not a model.
        $settable = $this->browserSettableProperties($context);
        foreach (Ast::find($method->stmts ?? [], fn (Node $n) => $n instanceof Expr\PropertyFetch && $n->var instanceof Expr\Variable && $n->var->name === 'this') as $fetch) {
            /** @var Expr\PropertyFetch $fetch */
            $name = $fetch->name instanceof Node\Identifier ? $fetch->name->toString() : null;
            if ($name !== null && in_array($name, $settable, true)) {
                $out[] = 'this->'.$name;
            }
        }

        return array_values(array_unique($out));
    }

    /**
     * Model::find($id) / Model::where('id', $this->selected)->first(): a lookup keyed by a client value,
     * not scoped to the current user.
     *
     * @param list<string> $clientValues
     */
    private function clientChosenLookup(Expr $expr, array $clientValues, Project $project): ?string
    {
        $root = $this->chainRoot($expr);
        if (! $root instanceof Expr\StaticCall) {
            return null;
        }
        $class = Ast::className($root);
        if ($class === null || ! $project->models()->isModel($class)) {
            return null;
        }
        $hasLookup = Ast::find($expr, fn (Node $n) => in_array(Ast::callName($n), self::LOOKUPS, true)) !== [];
        if (! $hasLookup || ! $this->mentionsAny($expr, $clientValues) || $this->mentionsCurrentUser($expr)) {
            return null;
        }

        return $class;
    }

    /** @param list<string> $clientValues */
    private function mentionsAny(Node $node, array $clientValues): bool
    {
        return Ast::find($node, function (Node $n) use ($clientValues): bool {
            if ($n instanceof Expr\Variable && is_string($n->name)) {
                return in_array($n->name, $clientValues, true);
            }
            if ($n instanceof Expr\PropertyFetch && $n->var instanceof Expr\Variable && $n->var->name === 'this' && $n->name instanceof Node\Identifier) {
                return in_array('this->'.$n->name->toString(), $clientValues, true);
            }

            return false;
        }) !== [];
    }

    /** @return list<string> */
    private function browserSettableProperties(FunctionContext $context): array
    {
        $out = [];
        foreach ($context->class?->node->getProperties() ?? [] as $property) {
            if (! $property->isPublic() || $property->isStatic()) {
                continue;
            }
            $locked = array_filter(Ast::attributeNames($property), fn ($a) => Ast::shortName($a) === 'Locked') !== [];
            $isModel = array_filter(Ast::typeNames($property->type), fn ($t) => $context->project->models()->isModel($t)) !== [];
            if ($locked || $isModel) {
                continue;
            }
            foreach ($property->props as $prop) {
                $out[] = $prop->name->toString();
            }
        }

        return $out;
    }

    private function mentionsCurrentUser(Node $node): bool
    {
        return Ast::find($node, fn (Node $n) => ($n instanceof Expr\FuncCall && Ast::callName($n) === 'auth')
            || ($n instanceof Expr\StaticCall && Ast::isFacade($n, 'Auth'))
            || (($n instanceof Expr\MethodCall || $n instanceof Expr\NullsafeMethodCall) && Ast::callName($n) === 'user')) !== [];
    }

    private function chainRoot(Expr $expr): Expr
    {
        $current = $expr;
        $guard = 0;
        while (($current instanceof Expr\MethodCall || $current instanceof Expr\NullsafeMethodCall) && $guard++ < 64) {
            $current = $current->var;
        }

        return $current;
    }
}
