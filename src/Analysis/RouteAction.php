<?php

declare(strict_types=1);

namespace Plumbline\Analysis;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use Plumbline\Project\ClassInfo;
use Plumbline\Project\PhpFile;
use Plumbline\Project\Project;
use Plumbline\Project\Route;

/** The code behind a route (a controller method or a closure) and what it does to models. */
final class RouteAction
{
    /** Model methods that change or delete an existing record. */
    private const MUTATORS = [
        'update', 'delete', 'forcedelete', 'save', 'restore', 'increment', 'decrement', 'touch', 'push', 'sync',
        'attach', 'detach', 'toggle', 'syncwithoutdetaching', 'updatequietly', 'deletequietly', 'savequietly',
        'forcedeletequietly', 'updateexistingpivot', 'incrementquietly', 'decrementquietly',
    ];

    /** Calls that perform (or delegate to) an authorization decision. */
    private const AUTHZ_CALLS = [
        'authorize', 'authorizeforuser', 'authorizeresource', 'can', 'cannot', 'cant', 'allows', 'denies', 'inspect',
        'check', 'any', 'none', 'is', 'isnot', 'hasrole', 'hasanyrole', 'hasallroles', 'haspermissionto',
        'hasanypermission', 'haspermission', 'hasdirectpermission', 'policy', 'isadmin', 'issuperadmin', 'isowner',
        'ownedby', 'isownedby', 'belongsto', 'abort_if', 'abort_unless', 'abort', 'gate', 'authorized',
    ];

    private function __construct(
        public readonly Node\FunctionLike $function,
        public readonly ?ClassInfo $class,
        public readonly PhpFile $file,
        private readonly Project $project,
    ) {
    }

    /** Wrap any method (e.g. a Livewire action) to reuse the authorization-evidence checks. */
    public static function forMethod(Stmt\ClassMethod $method, ClassInfo $class, Project $project): self
    {
        return new self($method, $class, $class->file, $project);
    }

    public static function for(Route $route, Project $project): ?self
    {
        if ($route->closure !== null) {
            $file = $project->file($route->file);

            return $file !== null ? new self($route->closure, null, $file, $project) : null;
        }
        if ($route->controller === null || $route->method === null) {
            return null;
        }
        $class = $project->classes()->get($route->controller);
        $method = $class?->method($route->method);
        if ($class === null || $method === null) {
            return null;
        }

        return new self($method, $class, $class->file, $project);
    }

    public function name(): string
    {
        return $this->class !== null && $this->function instanceof Stmt\ClassMethod
            ? $this->class->shortName().'@'.$this->function->name->toString()
            : 'closure in '.$this->file->relativePath;
    }

    public function line(): int
    {
        return $this->function->getStartLine();
    }

    /**
     * Parameters bound from the URL by route-model binding: name => model class.
     *
     * @return array<string, string>
     */
    public function boundModels(): array
    {
        $out = [];
        foreach ($this->function->getParams() as $param) {
            $name = Ast::varName($param->var);
            foreach (Ast::typeNames($param->type) as $type) {
                if ($name !== null && $this->project->models()->isModel($type)) {
                    $out[$name] = $type;
                }
            }
        }

        return $out;
    }

    /**
     * Writes to a route-bound model: [variable, model, call].
     *
     * @return list<array{0: string, 1: string, 2: Expr\MethodCall|Expr\NullsafeMethodCall}>
     */
    public function boundModelWrites(): array
    {
        $bound = $this->boundModels();
        // $post = Post::whereKey($post->id)->where('user_id', $user->id)->first(): no longer the URL's record.
        foreach (Ast::find($this->body(), fn (Node $n) => $n instanceof Expr\Assign) as $assign) {
            /** @var Expr\Assign $assign */
            unset($bound[(string) Ast::varName($assign->var)]);
        }
        $out = [];
        foreach ($this->mutatorCalls() as $call) {
            $root = $this->chainRoot($call);
            $name = Ast::varName($root);
            if ($name !== null && isset($bound[$name])) {
                $out[] = [$name, $bound[$name], $call];
            }
        }

        return $out;
    }

    /**
     * Any change to an existing record: bound models, Post::find($id)->delete(), Post::where(...)->update(),
     * $post = Post::findOrFail($id); $post->save(), Post::destroy($id).
     *
     * @return list<array{0: string, 1: Node}> [model short name, call]
     */
    public function existingRecordWrites(): array
    {
        $models = $this->project->models();
        $types = $this->boundModels();
        foreach (Ast::find($this->body(), fn (Node $n) => $n instanceof Expr\Assign) as $assign) {
            /** @var Expr\Assign $assign */
            $name = Ast::varName($assign->var);
            $root = $this->chainRoot($assign->expr);
            if ($name !== null && $root instanceof Expr\StaticCall && $models->isModel(Ast::className($root))) {
                $types[$name] = (string) Ast::className($root);
            }
        }

        $out = [];
        foreach ($this->mutatorCalls() as $call) {
            $root = $this->chainRoot($call);
            $name = Ast::varName($root);
            if ($name !== null && isset($types[$name])) {
                $out[] = [(string) Ast::shortName($types[$name]), $call];
            } elseif ($root instanceof Expr\StaticCall && $models->isModel(Ast::className($root))) {
                $out[] = [(string) Ast::shortName(Ast::className($root)), $call];
            }
        }
        foreach (Ast::find($this->body(), fn (Node $n) => $n instanceof Expr\StaticCall && Ast::callName($n) === 'destroy') as $call) {
            /** @var Expr\StaticCall $call */
            if ($models->isModel(Ast::className($call))) {
                $out[] = [(string) Ast::shortName(Ast::className($call)), $call];
            }
        }

        return $out;
    }

    /** Anything that looks like an authorization decision in the action, its FormRequests or controller. */
    public function hasAuthorizationEvidence(): bool
    {
        if (Ast::find($this->body(), fn (Node $n) => $this->isAuthorizationNode($n)) !== []) {
            return true;
        }

        // $this->ensureOwned($workspace, $policy): a same-class helper that checks access.
        if ($this->delegatesAuthorization()) {
            return true;
        }

        // $request->validate(['installation_key' => 'exists:installations,key']): knowing the secret is the access check.
        if ($this->requiresSecret($this->function)) {
            return true;
        }

        // Controller-wide: $this->authorizeResource() in the constructor, or authorization attributes.
        if ($this->class !== null) {
            foreach ($this->project->classes()->lineage($this->class->name) as $name) {
                $class = $this->project->classes()->get($name);
                if ($class === null) {
                    break;
                }
                $constructor = $class->method('__construct');
                if ($constructor !== null && Ast::find($constructor, fn (Node $n) => Ast::callName($n) === 'authorizeresource') !== []) {
                    return true;
                }
                if ($this->hasAuthorizationAttribute($class->attributes())) {
                    return true;
                }
            }
        }
        if ($this->hasAuthorizationAttribute(Ast::attributeNames($this->function))) {
            return true;
        }

        // A FormRequest whose authorize() does more than `return true;`
        $classes = $this->project->classes();
        foreach ($this->function->getParams() as $param) {
            foreach (Ast::typeNames($param->type) as $type) {
                $short = (string) Ast::shortName($type);
                if (! str_ends_with($short, 'Request') || $short === 'Request') {
                    continue;
                }
                $request = $classes->get($type);
                if ($request === null) {
                    return true; // A vendor FormRequest: we can't see it, so assume it authorizes.
                }
                if (! $classes->isFormRequest($type)) {
                    continue;
                }
                $authorize = null;
                foreach ($classes->lineage($type) as $ancestor) {
                    $authorize ??= $classes->get($ancestor)?->method('authorize');
                }
                if ($authorize !== null && ! $this->returnsTrueOnly($authorize)) {
                    return true;
                }
                // Validation that checks ownership: new ValidInvitation($this->user()), Rule::exists(...)->where('user_id', ...)
                $rules = $request->method('rules');
                if ($rules !== null && ($this->mentionsCurrentUserOrThisUser($rules) || $this->requiresSecret($rules))) {
                    return true;
                }
            }
        }

        return false;
    }

    /** Anything that checks who the user is: auth(), Auth::, $request->user(), Gate... */
    public function referencesCurrentUser(): bool
    {
        return Ast::find($this->body(), function (Node $n): bool {
            if ($n instanceof Expr\FuncCall) {
                return in_array(Ast::callName($n), ['auth', 'abort', 'abort_if', 'abort_unless', 'policy'], true);
            }
            if ($n instanceof Expr\StaticCall) {
                return Ast::isFacade($n, 'Auth') || Ast::isFacade($n, 'Gate');
            }
            if ($n instanceof Expr\MethodCall || $n instanceof Expr\NullsafeMethodCall) {
                return in_array(Ast::callName($n), ['user', 'authorize', 'can', 'cannot', 'hasvalidsignature', 'hasvalidrelativesignature'], true);
            }

            return false;
        }) !== [] || $this->hasAuthorizationEvidence();
    }

    /** @return list<Node> */
    private function body(): array
    {
        if ($this->function instanceof Expr\ArrowFunction) {
            return [$this->function->expr];
        }

        return $this->function->getStmts() ?? [];
    }

    /** @return list<Expr\MethodCall|Expr\NullsafeMethodCall> */
    private function mutatorCalls(): array
    {
        /** @var list<Expr\MethodCall|Expr\NullsafeMethodCall> $calls */
        $calls = Ast::find($this->body(), fn (Node $n) => ($n instanceof Expr\MethodCall || $n instanceof Expr\NullsafeMethodCall)
            && in_array(Ast::callName($n), self::MUTATORS, true));

        return $calls;
    }

    private function chainRoot(Expr $expr): Expr
    {
        $current = $expr;
        $guard = 0;
        while (($current instanceof Expr\MethodCall || $current instanceof Expr\NullsafeMethodCall
            || $current instanceof Expr\PropertyFetch || $current instanceof Expr\NullsafePropertyFetch) && $guard++ < 64) {
            $current = $current->var;
        }

        return $current;
    }

    private function isAuthorizationNode(Node $node): bool
    {
        if ($node instanceof Expr\StaticCall && Ast::isFacade($node, 'Gate')) {
            return true;
        }
        if ($node instanceof Expr\FuncCall || $node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall || $node instanceof Expr\StaticCall) {
            if (in_array(Ast::callName($node), self::AUTHZ_CALLS, true)) {
                return true;
            }
        }
        if ($node instanceof Expr\Throw_ && $node->expr instanceof Expr\New_) {
            $class = (string) Ast::shortName(Ast::className($node->expr));
            if (in_array($class, ['AuthorizationException', 'AccessDeniedHttpException', 'HttpException', 'UnauthorizedException'], true)) {
                return true;
            }
        }
        // if ($post->user_id !== $request->user()->id) ...
        if ($node instanceof Expr\BinaryOp\Identical || $node instanceof Expr\BinaryOp\NotIdentical
            || $node instanceof Expr\BinaryOp\Equal || $node instanceof Expr\BinaryOp\NotEqual) {
            return $this->mentionsCurrentUser($node->left) || $this->mentionsCurrentUser($node->right);
        }

        return false;
    }

    /**
     * A call to a helper on $this that receives the bound model, and either has an access-check name
     * (ensureOwned, checkAccess, authorizeTeam...) or whose own body contains an authorization decision.
     */
    private function delegatesAuthorization(): bool
    {
        $bound = array_keys($this->boundModels());
        if ($bound === [] || $this->class === null) {
            return false;
        }
        $calls = Ast::find($this->body(), fn (Node $n) => ($n instanceof Expr\MethodCall && $n->var instanceof Expr\Variable && $n->var->name === 'this')
            || ($n instanceof Expr\StaticCall && in_array(strtolower((string) Ast::className($n)), ['self', 'static'], true)));

        foreach ($calls as $call) {
            /** @var Expr\MethodCall|Expr\StaticCall $call */
            $passesBound = Ast::find(Ast::args($call), fn (Node $n) => $n instanceof Expr\Variable && in_array($n->name, $bound, true)) !== [];
            if (! $passesBound) {
                continue;
            }
            $name = $call->name instanceof Node\Identifier ? $call->name->toString() : '';
            $words = Ast::words($name);
            if (array_intersect($words, ['ensure', 'authorize', 'authorise', 'authorized', 'check', 'verify', 'guard', 'assert', 'can',
                'access', 'own', 'owns', 'owned', 'owner', 'ownership', 'permission', 'permissions', 'policy', 'deny', 'forbid',
                'abort', 'belongs', 'allowed', 'allow', 'restrict', 'gate', 'protect', 'authorization', 'authorisation']) !== []) {
                return true;
            }
            $name = strtolower($name);
            foreach ($this->project->classes()->lineage($this->class->name) as $className) {
                $helper = $this->project->classes()->get($className)?->method($name);
                if ($helper !== null) {
                    if (Ast::find($helper->stmts ?? [], fn (Node $n) => $this->isAuthorizationNode($n)) !== []) {
                        return true;
                    }
                    break;
                }
            }
        }

        return false;
    }

    /** An `exists:` rule on a key/token/code/secret column: the caller must know a secret value. */
    private function requiresSecret(Node $node): bool
    {
        return Ast::find($node, fn (Node $n) => $n instanceof Node\Scalar\String_
            && preg_match('/(^|\|)exists:[^|]*(key|token|code|secret|hash|password|passcode|pin)\b/i', $n->value)) !== [];
    }

    private function mentionsCurrentUserOrThisUser(Node $node): bool
    {
        return Ast::find($node, function (Node $n): bool {
            if ($n instanceof Expr\MethodCall && Ast::callName($n) === 'user') {
                return true;
            }
            if ($n instanceof Expr\FuncCall) {
                return Ast::callName($n) === 'auth';
            }

            return $n instanceof Expr\StaticCall && Ast::isFacade($n, 'Auth');
        }) !== [];
    }

    private function mentionsCurrentUser(Expr $expr): bool
    {
        return Ast::find($expr, function (Node $n): bool {
            if ($n instanceof Expr\FuncCall) {
                return Ast::callName($n) === 'auth';
            }
            if ($n instanceof Expr\StaticCall) {
                return Ast::isFacade($n, 'Auth');
            }

            return ($n instanceof Expr\MethodCall || $n instanceof Expr\NullsafeMethodCall) && Ast::callName($n) === 'user';
        }) !== [];
    }

    /** @param list<string> $attributes */
    private function hasAuthorizationAttribute(array $attributes): bool
    {
        foreach ($attributes as $attribute) {
            if (in_array(Ast::shortName($attribute), ['Can', 'Authorize', 'Middleware', 'Gate', 'Policy'], true)) {
                return true;
            }
        }

        return false;
    }

    private function returnsTrueOnly(Stmt\ClassMethod $method): bool
    {
        $stmts = $method->stmts ?? [];

        return count($stmts) === 1 && $stmts[0] instanceof Stmt\Return_
            && $stmts[0]->expr instanceof Expr\ConstFetch && strtolower($stmts[0]->expr->name->toString()) === 'true';
    }
}
