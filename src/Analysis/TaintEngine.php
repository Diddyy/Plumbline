<?php

declare(strict_types=1);

namespace Plumbline\Analysis;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use Plumbline\Finding;
use Plumbline\Project\ClassInfo;
use Plumbline\Project\PhpFile;
use Plumbline\Project\Project;
use Plumbline\Rules\TaintRule;

/**
 * Walks every function body once, in source order, tracking which variables hold user input,
 * and offers each node to the taint rules.
 *
 * Scope is intra-procedural on purpose: flows through helper methods are not followed. That keeps
 * results explainable ("this variable came from $request->input('sort') on line 12").
 */
final class TaintEngine
{
    private const BRANCHING = [
        Stmt\If_::class, Stmt\ElseIf_::class, Stmt\Else_::class, Stmt\Switch_::class, Stmt\Case_::class,
        Stmt\While_::class, Stmt\Do_::class, Stmt\For_::class, Stmt\Foreach_::class, Stmt\Catch_::class,
        Expr\Closure::class, Expr\ArrowFunction::class, Expr\Ternary::class, Expr\Match_::class,
    ];

    /** @var list<Finding> */
    private array $findings = [];

    private Scope $scope;

    private Evaluator $evaluator;

    private FunctionContext $context;

    private int $depth = 0;

    /** @param list<TaintRule> $rules */
    public function __construct(private readonly Project $project, private readonly array $rules)
    {
        $this->scope = new Scope();
    }

    /** @return list<Finding> */
    public function run(): array
    {
        if ($this->rules === []) {
            return [];
        }
        foreach ($this->project->phpFiles() as $file) {
            $this->analyseFile($file);
        }

        return $this->findings;
    }

    private function analyseFile(PhpFile $file): void
    {
        $stmts = $file->stmts();

        // Top-level code (route files, config, plain scripts).
        $this->analyse($file, null, null, $stmts);

        foreach (Ast::find($stmts, fn (Node $n) => $n instanceof Stmt\Function_) as $function) {
            /** @var Stmt\Function_ $function */
            $this->analyse($file, null, $function, $function->stmts);
        }

        foreach (Ast::find($stmts, fn (Node $n) => $n instanceof Stmt\Class_ && $n->name !== null) as $classNode) {
            /** @var Stmt\Class_ $classNode */
            $class = $this->project->classes()->get($classNode->namespacedName?->toString());
            foreach ($classNode->getMethods() as $method) {
                $this->analyse($file, $class, $method, $method->stmts ?? []);
            }
        }
    }

    /** @param list<Node> $stmts */
    private function analyse(PhpFile $file, ?ClassInfo $class, ?Node\FunctionLike $function, array $stmts): void
    {
        $this->scope = new Scope();
        $this->context = new FunctionContext($this->project, $file, $class, $function);
        $this->evaluator = new Evaluator($this->scope, $this->context);
        $this->depth = 0;

        if ($function !== null) {
            $this->registerParams($function);
        }
        foreach ($stmts as $stmt) {
            $this->visit($stmt, $function === null);
        }
    }

    private function visit(Node $node, bool $topLevel): void
    {
        // Classes and named functions get their own pass; at the top level we skip them.
        if ($node instanceof Stmt\ClassLike || ($topLevel && $node instanceof Stmt\Function_)) {
            return;
        }

        $this->enter($node);

        $branching = $this->isBranching($node);
        if ($branching) {
            $this->depth++;
        }
        $localOnly = ($node instanceof Stmt\If_ || $node instanceof Stmt\ElseIf_) && Ast::isLocalOnlyCondition($node->cond);
        $guard = ($node instanceof Stmt\If_ || $node instanceof Stmt\ElseIf_) ? $node->cond : null;
        // `$cond ? <guarded> : ...` guards its "if" branch the same way an if-statement does.
        $guardedBranch = 'stmts';
        if ($node instanceof Expr\Ternary && $node->if !== null) {
            $guard = $node->cond;
            $guardedBranch = 'if';
        }
        foreach ($node->getSubNodeNames() as $name) {
            if ($name === 'stmts' && $localOnly) {
                continue; // code that never runs in production
            }
            if ($name === $guardedBranch && $guard !== null) {
                $this->scope->pushGuard($guard);
            }
            $child = $node->$name;
            if ($child instanceof Node) {
                $this->visit($child, $topLevel);
            } elseif (is_array($child)) {
                foreach ($child as $item) {
                    if ($item instanceof Node) {
                        $this->visit($item, $topLevel);
                    }
                }
            }
            if ($name === $guardedBranch && $guard !== null) {
                $this->scope->popGuard();
            }
        }
        if ($branching) {
            $this->depth--;
        }

        $this->leave($node);
    }

    private function isBranching(Node $node): bool
    {
        foreach (self::BRANCHING as $class) {
            if ($node instanceof $class) {
                return true;
            }
        }

        return false;
    }

    private function enter(Node $node): void
    {
        if ($node instanceof Expr\Closure || $node instanceof Expr\ArrowFunction) {
            $this->registerParams($node);
        }

        if ($node instanceof Stmt\Foreach_) {
            $value = $this->evaluator->evaluate($node->expr);
            if ($value->tainted) {
                foreach ([$node->keyVar, $node->valueVar] as $target) {
                    $name = Ast::varName($target);
                    if ($name !== null) {
                        $this->scope->set($name, Value::tainted($value->source), true);
                    }
                }
            }
        }

        $this->recordValidation($node);

        foreach ($this->rules as $rule) {
            foreach ($rule->inspect($node, $this->scope, $this->context) as $finding) {
                $this->findings[] = $finding;
            }
        }
    }

    private function leave(Node $node): void
    {
        if ($node instanceof Expr\Assign || $node instanceof Expr\AssignRef) {
            $this->assign($node->var, $this->evaluator->evaluate($node->expr), $node->expr);
        } elseif ($node instanceof Expr\AssignOp\Concat || $node instanceof Expr\AssignOp\Coalesce) {
            $value = $this->evaluator->evaluate($node->expr);
            if ($value->tainted) {
                $this->assign($node->var, $value);
            }
        } elseif ($node instanceof Stmt\Expression) {
            $this->allowlistGuard($node->expr);
        } elseif ($node instanceof Stmt\If_) {
            $this->allowlistIf($node);
        }
    }

    private function assign(Expr $target, Value $value, ?Expr $source = null): void
    {
        $name = Ast::varName($target);
        if ($name !== null) {
            $this->scope->set($name, $value, $this->depth > 0);
            if ($source !== null) {
                $this->scope->setType($name, (new Types($this->scope, $this->context))->classOf($source));
            }

            return;
        }

        // $data['x'] = $tainted taints $data; [$a, $b] = $tainted taints both.
        if ($target instanceof Expr\ArrayDimFetch && $value->tainted) {
            $base = $target->var;
            while ($base instanceof Expr\ArrayDimFetch) {
                $base = $base->var;
            }
            $baseName = Ast::varName($base);
            if ($baseName !== null) {
                $this->scope->set($baseName, $value->withoutBag(), true);
            }
        }

        if ($target instanceof Expr\List_ || $target instanceof Expr\Array_) {
            foreach ($target->items as $item) {
                if ($item !== null) {
                    $this->assign($item->value, $value->withoutBag());
                }
            }
        }
    }

    private function registerParams(Node\FunctionLike $function): void
    {
        $classes = $this->project->classes();
        $userInput = $this->context->paramsAreUserInput($function);

        foreach ($function->getParams() as $param) {
            $name = Ast::varName($param->var);
            if ($name === null) {
                continue;
            }
            $types = Ast::typeNames($param->type);
            foreach ($types as $type) {
                if (str_contains($type, '\\') || ctype_upper($type[0] ?? '')) {
                    $this->scope->setType($name, $type);
                    break;
                }
            }

            $isRequest = false;
            foreach ($types as $type) {
                $short = (string) Ast::shortName($type);
                if ($short === 'Request' || str_ends_with($short, 'Request') && ($classes->get($type) === null || $classes->isFormRequest($type))) {
                    $isRequest = true;
                    $info = $classes->get($type);
                    if ($info !== null) {
                        $this->scope->addValidation(ValidationRules::fromFormRequest($info));
                    }
                }
            }
            if ($isRequest) {
                $this->scope->set($name, Value::request(), false);
                continue;
            }

            $scalarish = $types === [] || array_diff($types, ['string', 'mixed', 'array']) === [];
            if ($userInput && $scalarish) {
                $label = $this->context->isLivewire ? 'Livewire action argument $'.$name : 'route parameter $'.$name;
                $this->scope->set($name, Value::tainted($label), false);
            } else {
                $this->scope->set($name, Value::clean(), false);
            }
        }
        // Closure `use ($var)` needs nothing: one scope is shared by variable name.
    }

    /** $request->validate([...]), $this->validate($request, [...]), Validator::make($data, [...]) */
    private function recordValidation(Node $node): void
    {
        $rules = null;
        if ($node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall) {
            $method = Ast::callName($node);
            if ($method === 'validate') {
                $isThis = $node->var instanceof Expr\Variable && $node->var->name === 'this';
                $rules = Ast::arg($node, $isThis ? 1 : 0, 'rules');
            } elseif ($method === 'validatewithbag') {
                $rules = Ast::arg($node, 1, 'rules');
            }
        } elseif ($node instanceof Expr\StaticCall && Ast::isFacade($node, 'Validator') && Ast::callName($node) === 'make') {
            $rules = Ast::arg($node, 1, 'rules');
        }

        if ($rules !== null) {
            $this->scope->addValidation(ValidationRules::fromArray($rules));
        }
    }

    /** abort_unless(in_array($sort, [...]), 400);  abort_if(! in_array(...)) */
    private function allowlistGuard(Expr $expr): void
    {
        $name = $expr instanceof Expr\FuncCall ? Ast::callName($expr) : null;
        if ($name === null || ! in_array($name, ['abort_unless', 'abort_if', 'throw_unless', 'throw_if'], true)) {
            return;
        }
        /** @var Expr\FuncCall $expr */
        $condition = Ast::arg($expr, 0);
        // abort_unless(in_array(...)) and abort_if(! in_array(...)) are allowlists;
        // abort_if(in_array($x, $blocked)) is a blocklist and proves nothing.
        $negated = $condition instanceof Expr\BooleanNot;
        $isUnless = str_ends_with($name, '_unless');
        if ($isUnless === $negated) {
            return;
        }
        foreach ($this->allowlistedVars($condition) as $var) {
            $this->scope->sanitise($var);
        }
        $positive = $condition instanceof Expr\BooleanNot ? $condition->expr : $condition;
        foreach (RedirectGuards::checkedVars($positive) as $var) {
            $this->scope->markPrefixChecked($var);
        }
    }

    /** if (! in_array($sort, $allowed)) { return / throw / abort } */
    private function allowlistIf(Stmt\If_ $if): void
    {
        if (! $if->cond instanceof Expr\BooleanNot || $if->stmts === []) {
            return;
        }
        $last = end($if->stmts);
        $exits = $last instanceof Stmt\Return_
            || ($last instanceof Stmt\Expression && ($last->expr instanceof Expr\Throw_ || $last->expr instanceof Expr\Exit_
                || ($last->expr instanceof Expr\FuncCall && in_array(Ast::callName($last->expr), ['abort', 'abort_if', 'abort_unless'], true))));
        if (! $exits) {
            return;
        }
        foreach ($this->allowlistedVars($if->cond->expr) as $name) {
            $this->scope->sanitise($name);
        }
        foreach (RedirectGuards::checkedVars($if->cond->expr) as $name) {
            $this->scope->markPrefixChecked($name);
        }
    }

    /** @return list<string> variables checked by in_array()/array_key_exists() in the expression */
    private function allowlistedVars(?Expr $expr): array
    {
        if ($expr instanceof Expr\BooleanNot) {
            $expr = $expr->expr;
        }
        $names = [];
        foreach (Ast::find($expr, fn (Node $n) => $n instanceof Expr\FuncCall && in_array(Ast::callName($n), ['in_array', 'array_key_exists', 'preg_match', 'ctype_digit', 'ctype_alnum', 'is_numeric'], true)) as $call) {
            /** @var Expr\FuncCall $call */
            $subject = Ast::callName($call) === 'array_key_exists' || Ast::callName($call) === 'preg_match' ? Ast::arg($call, Ast::callName($call) === 'preg_match' ? 1 : 0) : Ast::arg($call, 0);
            $name = Ast::varName($subject);
            if ($name !== null) {
                $names[] = $name;
            }
        }

        return $names;
    }
}
