<?php

declare(strict_types=1);

namespace Plumbline\Project;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use Plumbline\Analysis\Ast;

/**
 * Reconstructs the application's routes statically, the way Laravel would register them:
 * route files and how they are loaded (bootstrap/app.php, RouteServiceProvider), nested
 * groups, prefixes, controller groups, resources, and middleware from groups, routes and
 * controllers.
 *
 * Routes in files whose loading context we can't determine are kept but marked
 * contextKnown = false, and access-control rules ignore them.
 */
final class RouteIndex
{
    private const VERBS = [
        'get' => ['GET', 'HEAD'], 'post' => ['POST'], 'put' => ['PUT'], 'patch' => ['PATCH'],
        'delete' => ['DELETE'], 'options' => ['OPTIONS'], 'any' => ['ANY'],
    ];

    private const RESOURCE_ACTIONS = [
        'index' => [['GET', 'HEAD'], ''],
        'create' => [['GET', 'HEAD'], '/create'],
        'store' => [['POST'], ''],
        'show' => [['GET', 'HEAD'], '/{id}'],
        'edit' => [['GET', 'HEAD'], '/{id}/edit'],
        'update' => [['PUT', 'PATCH'], '/{id}'],
        'destroy' => [['DELETE'], '/{id}'],
    ];

    private const CLASS_ALIASES = [
        'Authenticate' => 'auth', 'AuthenticateWithBasicAuth' => 'auth.basic', 'EnsureEmailIsVerified' => 'verified',
        'Authorize' => 'can', 'ValidateSignature' => 'signed', 'RedirectIfAuthenticated' => 'guest',
        'ThrottleRequests' => 'throttle', 'ThrottleRequestsWithRedis' => 'throttle', 'VerifyCsrfToken' => 'csrf',
        'ValidateCsrfToken' => 'csrf', 'PreventRequestForgery' => 'csrf', 'SubstituteBindings' => 'bindings',
        'RequirePassword' => 'password.confirm', 'EnsureFrontendRequestsAreStateful' => 'stateful',
        'AuthenticateSession' => 'auth.session', 'CheckAbilities' => 'abilities', 'CheckForAnyAbility' => 'ability',
        'RoleMiddleware' => 'role', 'PermissionMiddleware' => 'permission', 'RoleOrPermissionMiddleware' => 'role_or_permission',
        'SetCacheHeaders' => 'cache.headers', 'HandlePrecognitiveRequests' => 'precognitive',
    ];

    /** @var list<Route> */
    private array $routes = [];

    /** @var array<string, list<string>> */
    private array $groups = [
        'web' => ['encryptcookies', 'addqueuedcookiestoresponse', 'startsession', 'sharederrorsfromsession', 'csrf', 'bindings'],
        'api' => ['bindings'],
    ];

    /** @var array<string, string> custom alias => normalised name */
    private array $aliases = [];

    /** @var list<array{pattern: string, file: string, line: int}> */
    private array $csrfExclusions = [];

    /** @var array<string, true> */
    private array $processed = [];

    public function __construct(private readonly Project $project)
    {
        $this->readBootstrapMiddleware();
        $this->readHttpKernel();
        $this->readCsrfMiddleware();

        foreach ($this->entryPoints() as [$file, $context]) {
            $this->processFile($file, $context);
        }

        foreach ($project->phpFiles() as $file) {
            $rel = $file->relativePath;
            if (str_starts_with($rel, 'routes/') && ! isset($this->processed[$rel])
                && ! in_array($rel, ['routes/console.php', 'routes/channels.php'], true)) {
                $this->processFile($rel, $this->context(known: false));
            }
        }
    }

    /** @return list<Route> */
    public function all(): array
    {
        return $this->routes;
    }

    /** @return list<array{pattern: string, file: string, line: int}> */
    public function csrfExclusions(): array
    {
        return $this->csrfExclusions;
    }

    // ---------------------------------------------------------------- entry points

    /** @return list<array{0: string, 1: array<string, mixed>}> */
    private function entryPoints(): array
    {
        $entries = [];
        $bootstrap = $this->project->file('bootstrap/app.php');
        if ($bootstrap !== null) {
            foreach (Ast::find($bootstrap->stmts(), fn (Node $n) => $n instanceof Expr\MethodCall && Ast::callName($n) === 'withrouting') as $call) {
                /** @var Expr\MethodCall $call */
                $apiPrefix = Ast::stringValue(Ast::arg($call, 99, 'apiPrefix')) ?? 'api';
                foreach ($this->filesIn(Ast::arg($call, 0, 'web'), $bootstrap) as $file) {
                    $entries[] = [$file, $this->context(['web'])];
                }
                foreach ($this->filesIn(Ast::arg($call, 1, 'api'), $bootstrap) as $file) {
                    $entries[] = [$file, $this->context(['api'], $apiPrefix)];
                }
                foreach (['then', 'using'] as $name) {
                    $closure = Ast::arg($call, 99, $name);
                    if ($closure instanceof Expr\Closure) {
                        $this->processStatements($closure->stmts, $this->context(), $bootstrap);
                    }
                }
            }
        }

        $provider = $this->project->file('app/Providers/RouteServiceProvider.php');
        if ($provider !== null) {
            foreach (Ast::find($provider->stmts(), fn (Node $n) => $n instanceof Stmt\ClassMethod) as $method) {
                /** @var Stmt\ClassMethod $method */
                $this->processStatements($method->stmts ?? [], $this->context(), $provider);
            }
        }

        // A plain skeleton without either file: Laravel's defaults.
        if ($entries === [] && $provider === null) {
            $entries[] = ['routes/web.php', $this->context(['web'])];
            $entries[] = ['routes/api.php', $this->context(['api'], 'api')];
        }

        return $entries;
    }

    /** @return list<string> route files referenced by a path expression (or an array of them) */
    private function filesIn(?Expr $expr, PhpFile $from): array
    {
        if ($expr === null) {
            return [];
        }
        if ($expr instanceof Expr\Array_) {
            $out = [];
            foreach ($expr->items as $item) {
                if ($item !== null) {
                    array_push($out, ...$this->filesIn($item->value, $from));
                }
            }

            return $out;
        }
        $path = $this->resolvePath($expr, $from);

        return $path !== null ? [$path] : [];
    }

    private function resolvePath(Expr $expr, PhpFile $from): ?string
    {
        $strings = '';
        $usesDir = false;
        foreach (Ast::find($expr, fn (Node $n) => $n instanceof Node\Scalar\String_ || $n instanceof Node\Scalar\MagicConst\Dir) as $part) {
            if ($part instanceof Node\Scalar\MagicConst\Dir) {
                $usesDir = true;
            } else {
                /** @var Node\Scalar\String_ $part */
                $strings .= $part->value;
            }
        }
        if ($strings === '') {
            return null;
        }
        $path = $usesDir ? dirname($from->relativePath).'/'.ltrim($strings, '/') : ltrim($strings, '/');

        // Normalise ../ segments.
        $segments = [];
        foreach (explode('/', str_replace('\\', '/', $path)) as $segment) {
            if ($segment === '..') {
                array_pop($segments);
            } elseif ($segment !== '.' && $segment !== '') {
                $segments[] = $segment;
            }
        }

        return implode('/', $segments);
    }

    // ---------------------------------------------------------------- walking route files

    /**
     * @param list<string> $middleware
     * @return array<string, mixed>
     */
    private function context(array $middleware = [], string $prefix = '', bool $known = true): array
    {
        return ['middleware' => $middleware, 'without' => [], 'prefix' => $prefix, 'controller' => null, 'known' => $known, 'only' => null, 'except' => []];
    }

    /** @param array<string, mixed> $context */
    private function processFile(string $relative, array $context): void
    {
        if (isset($this->processed[$relative])) {
            return;
        }
        $this->processed[$relative] = true;
        $file = $this->project->file($relative);
        if ($file !== null) {
            $this->processStatements($file->stmts(), $context, $file);
        }
    }

    /**
     * @param array<Node> $stmts
     * @param array<string, mixed> $context
     */
    private function processStatements(array $stmts, array $context, PhpFile $file): void
    {
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Expression) {
                $this->handleExpression($stmt->expr, $context, $file);
            } elseif ($stmt instanceof Stmt\If_) {
                // if (app()->environment('local')) { Route::... } never registers in production.
                if (! Ast::isLocalOnlyCondition($stmt->cond)) {
                    $this->processStatements($stmt->stmts, $context, $file);
                }
                foreach ($stmt->elseifs as $elseif) {
                    $this->processStatements($elseif->stmts, $context, $file);
                }
                if ($stmt->else !== null) {
                    $this->processStatements($stmt->else->stmts, $context, $file);
                }
            } elseif ($stmt instanceof Stmt\ClassLike) {
                continue;
            } elseif (property_exists($stmt, 'stmts') && is_array($stmt->stmts)) {
                $this->processStatements($stmt->stmts, $context, $file);
            }
        }
    }

    /** @param array<string, mixed> $context */
    private function handleExpression(Expr $expr, array $context, PhpFile $file): void
    {
        if ($expr instanceof Expr\Include_) {
            $path = $this->resolvePath($expr->expr, $file);
            if ($path !== null) {
                $this->processFile($path, $context);
            }

            return;
        }

        $chain = $this->chain($expr);
        if ($chain === null) {
            // Not a route chain: look into closures passed to it ($this->routes(function () { ... })).
            if ($expr instanceof Expr\CallLike && ! $expr->isFirstClassCallable()) {
                foreach (Ast::args($expr) as $arg) {
                    if ($arg->value instanceof Expr\Closure) {
                        $this->processStatements($arg->value->stmts, $context, $file);
                    }
                }
            }

            return;
        }

        $attrs = $context;
        $registration = null;
        foreach ($chain as $call) {
            $name = Ast::callName($call);
            switch ($name) {
                case 'middleware':
                    array_push($attrs['middleware'], ...$this->normaliseAll($call));
                    break;
                case 'withoutmiddleware':
                    array_push($attrs['without'], ...$this->normaliseAll($call));
                    break;
                case 'prefix':
                    $attrs['prefix'] = $this->joinUri($attrs['prefix'], Ast::stringValue(Ast::arg($call, 0)) ?? '');
                    break;
                case 'controller':
                    $attrs['controller'] = Ast::stringValue(Ast::arg($call, 0));
                    break;
                case 'can':
                    $attrs['middleware'][] = 'can:'.implode(',', Ast::stringArgs($call));
                    break;
                case 'only':
                    $attrs['only'] = Ast::stringArgs($call);
                    break;
                case 'except':
                    $attrs['except'] = Ast::stringArgs($call);
                    break;
                case 'group':
                    $registration ??= $call;
                    break;
                default:
                    if ($name !== null && (isset(self::VERBS[$name]) || in_array($name, ['match', 'resource', 'apiresource', 'resources', 'apiresources', 'singleton', 'apisingleton'], true))) {
                        $registration ??= $call;
                    }
            }
        }

        if ($registration === null) {
            return;
        }
        if (Ast::callName($registration) === 'group') {
            $this->handleGroup($registration, $attrs, $file);
        } else {
            $this->addRoutes($registration, $attrs, $file);
        }
    }

    /** @return list<Expr\CallLike>|null calls from Route::x() outwards, or null if not a Route chain */
    private function chain(Expr $expr): ?array
    {
        $calls = [];
        $current = $expr;
        while ($current instanceof Expr\MethodCall) {
            array_unshift($calls, $current);
            $current = $current->var;
        }
        if ($current instanceof Expr\StaticCall && Ast::isFacade($current, 'Route')) {
            array_unshift($calls, $current);

            return $calls;
        }

        return null;
    }

    /** @param array<string, mixed> $attrs */
    private function handleGroup(Expr\CallLike $call, array $attrs, PhpFile $file): void
    {
        $args = $call->isFirstClassCallable() ? [] : Ast::args($call);
        // Legacy: Route::group(['middleware' => 'auth', 'prefix' => 'admin'], function () { ... })
        if (count($args) >= 2 && $args[0]->value instanceof Expr\Array_) {
            foreach ($args[0]->value->items as $item) {
                $key = $item !== null ? Ast::stringValue($item->key) : null;
                if ($key === 'middleware') {
                    array_push($attrs['middleware'], ...$this->normalise($item->value));
                } elseif ($key === 'prefix') {
                    $attrs['prefix'] = $this->joinUri($attrs['prefix'], Ast::stringValue($item->value) ?? '');
                } elseif ($key === 'controller') {
                    $attrs['controller'] = Ast::stringValue($item->value);
                }
            }
        }
        $target = $args !== [] ? end($args)->value : null;
        $attrs['only'] = null;
        $attrs['except'] = [];
        if ($target instanceof Expr\Closure) {
            $this->processStatements($target->stmts, $attrs, $file);
        } elseif ($target !== null) {
            $path = $this->resolvePath($target, $file);
            if ($path !== null) {
                $this->processFile($path, $attrs);
            }
        }
    }

    /** @param array<string, mixed> $attrs */
    private function addRoutes(Expr\CallLike $call, array $attrs, PhpFile $file): void
    {
        $name = (string) Ast::callName($call);

        if (in_array($name, ['resource', 'apiresource', 'singleton', 'apisingleton'], true)) {
            $this->addResource($name, Ast::stringValue(Ast::arg($call, 0)) ?? '', Ast::stringValue(Ast::arg($call, 1)), $attrs, $file, $call->getStartLine());

            return;
        }
        if (in_array($name, ['resources', 'apiresources'], true)) {
            $map = Ast::arg($call, 0);
            if ($map instanceof Expr\Array_) {
                foreach ($map->items as $item) {
                    if ($item !== null) {
                        $this->addResource(rtrim($name, 's'), Ast::stringValue($item->key) ?? '', Ast::stringValue($item->value), $attrs, $file, $call->getStartLine());
                    }
                }
            }

            return;
        }

        if ($name === 'match') {
            $verbs = array_map('strtoupper', Ast::stringList(Ast::arg($call, 0)));
            $uri = Ast::stringValue(Ast::arg($call, 1)) ?? '';
            $action = Ast::arg($call, 2, 'action');
        } else {
            $verbs = self::VERBS[$name];
            $uri = Ast::stringValue(Ast::arg($call, 0, 'uri')) ?? '';
            $action = Ast::arg($call, 1, 'action');
        }

        [$controller, $method, $closure] = $this->resolveAction($action, $attrs['controller']);
        $this->push($verbs, $this->joinUri($attrs['prefix'], $uri), $attrs, $file, $call->getStartLine(), $controller, $method, $closure);
    }

    /** @param array<string, mixed> $attrs */
    private function addResource(string $type, string $name, ?string $controller, array $attrs, PhpFile $file, int $line): void
    {
        $actions = self::RESOURCE_ACTIONS;
        if (str_starts_with($type, 'api')) {
            unset($actions['create'], $actions['edit']);
        }
        if (str_contains($type, 'singleton')) {
            $actions = array_intersect_key($actions, array_flip(['show', 'edit', 'update']));
            foreach ($actions as $key => [$verbs, $suffix]) {
                $actions[$key] = [$verbs, str_replace('/{id}', '', $suffix)];
            }
        }
        if (is_array($attrs['only'])) {
            $actions = array_intersect_key($actions, array_flip($attrs['only']));
        }
        $actions = array_diff_key($actions, array_flip($attrs['except']));

        $base = $this->joinUri($attrs['prefix'], $name);
        $param = '{'.rtrim((string) preg_replace('/.*[.\/]/', '', $name), 's').'}';
        foreach ($actions as $action => [$verbs, $suffix]) {
            $this->push($verbs, $base.str_replace('{id}', $param, $suffix), $attrs, $file, $line, $controller, $action, null);
        }
    }

    /**
     * @param list<string> $verbs
     * @param array<string, mixed> $attrs
     */
    private function push(array $verbs, string $uri, array $attrs, PhpFile $file, int $line, ?string $controller, ?string $method, ?Node\FunctionLike $closure): void
    {
        $declared = $attrs['middleware'];
        if ($controller !== null && $method !== null) {
            array_push($declared, ...$this->controllerMiddleware($controller, $method));
        }
        $without = $attrs['without'];

        $this->routes[] = new Route(
            $verbs,
            $uri,
            array_values(array_diff($this->expand($declared), $without)),
            $without,
            array_values(array_diff($declared, $without)),
            $file->relativePath,
            $line,
            (bool) $attrs['known'],
            $controller,
            $method,
            $closure,
        );
    }

    /** @return array{0: ?string, 1: ?string, 2: ?Node\FunctionLike} */
    private function resolveAction(?Expr $action, ?string $groupController): array
    {
        if ($action instanceof Expr\Closure || $action instanceof Expr\ArrowFunction) {
            return [null, null, $action];
        }
        if ($action instanceof Expr\Array_) {
            $first = $action->items[0] ?? null;
            $second = $action->items[1] ?? null;
            if ($first !== null && $first->key === null) {
                return [Ast::stringValue($first->value), $second !== null ? Ast::stringValue($second->value) : '__invoke', null];
            }
            foreach ($action->items as $item) {
                if ($item !== null && Ast::stringValue($item->key) === 'uses') {
                    return $this->resolveAction($item->value, $groupController);
                }
            }
        }
        $string = Ast::stringValue($action);
        if ($string === null) {
            return [null, null, null];
        }
        if (str_contains($string, '@')) {
            [$class, $method] = explode('@', $string, 2);

            return [$class, $method, null];
        }
        if ($groupController !== null) {
            return [$groupController, $string, null];
        }

        // Invokable controller: Route::post('/x', SomeController::class)
        return [$string, '__invoke', null];
    }

    private function joinUri(string $prefix, string $uri): string
    {
        return trim(trim($prefix, '/').'/'.trim($uri, '/'), '/');
    }

    // ---------------------------------------------------------------- middleware

    /** @return list<string> */
    private function normaliseAll(Expr\CallLike $call): array
    {
        $out = [];
        if (! $call->isFirstClassCallable()) {
            foreach (Ast::args($call) as $arg) {
                array_push($out, ...$this->normalise($arg->value));
            }
        }

        return $out;
    }

    /** @return list<string> */
    private function normalise(?Expr $expr): array
    {
        if ($expr === null) {
            return [];
        }
        if ($expr instanceof Expr\Array_) {
            $out = [];
            foreach ($expr->items as $item) {
                if ($item !== null) {
                    array_push($out, ...$this->normalise($item->value));
                }
            }

            return $out;
        }
        $string = Ast::stringValue($expr);
        if ($string !== null) {
            return [$this->alias($string)];
        }
        // Authorize::class.':update,post'
        if ($expr instanceof Expr\BinaryOp\Concat) {
            $left = Ast::stringValue($expr->left);
            $right = Ast::stringValue($expr->right);
            if ($left !== null && $right !== null) {
                return [$this->alias($left).(str_starts_with($right, ':') ? $right : ':'.$right)];
            }
        }
        // Authorize::using('update', 'post'), Authenticate::using('sanctum')
        if ($expr instanceof Expr\StaticCall && Ast::callName($expr) === 'using') {
            $class = Ast::className($expr);

            return [$this->alias((string) $class).':'.implode(',', Ast::stringArgs($expr))];
        }

        // A closure or something dynamic: unknown middleware.
        return ['(dynamic middleware)'];
    }

    private function alias(string $name): string
    {
        [$base, $params] = array_pad(explode(':', $name, 2), 2, null);
        if (isset($this->aliases[$base])) {
            $base = $this->aliases[$base];
        } elseif (str_contains($base, '\\') || ctype_upper($base[0] ?? '')) {
            $short = (string) Ast::shortName($base);
            $base = self::CLASS_ALIASES[$short] ?? strtolower($short);
        }

        return $params !== null ? $base.':'.$params : $base;
    }

    /**
     * @param list<string> $middleware
     * @return list<string>
     */
    private function expand(array $middleware): array
    {
        $out = [];
        foreach ($middleware as $name) {
            $out[] = $name;
            foreach ($this->groups[$name] ?? [] as $member) {
                $out[] = $member;
            }
        }

        return array_values(array_unique($out));
    }

    /**
     * Middleware a controller applies to one of its methods.
     *
     * @return list<string>
     */
    private function controllerMiddleware(string $controller, string $method): array
    {
        $out = [];
        foreach ($this->project->classes()->lineage($controller) as $name) {
            $class = $this->project->classes()->get($name);
            if ($class === null) {
                break;
            }

            // Laravel 11+: public static function middleware(): array { return ['auth', new Middleware('can:x', only: [...])]; }
            $static = $class->method('middleware');
            if ($static !== null && $static->isStatic()) {
                foreach (Ast::find($static->stmts ?? [], fn (Node $n) => $n instanceof Stmt\Return_) as $return) {
                    /** @var Stmt\Return_ $return */
                    if (! $return->expr instanceof Expr\Array_) {
                        continue;
                    }
                    foreach ($return->expr->items as $item) {
                        if ($item === null) {
                            continue;
                        }
                        $value = $item->value;
                        if ($value instanceof Expr\New_ && Ast::shortName(Ast::className($value)) === 'Middleware') {
                            $only = Ast::stringList(Ast::arg($value, 1, 'only'));
                            $except = Ast::stringList(Ast::arg($value, 2, 'except'));
                            if (($only === [] || in_array($method, $only, true)) && ! in_array($method, $except, true)) {
                                array_push($out, ...$this->normalise(Ast::arg($value, 0, 'middleware')));
                            }
                        } else {
                            array_push($out, ...$this->normalise($value));
                        }
                    }
                }
            }

            // Laravel <= 10: $this->middleware('auth')->only([...]) in the constructor.
            $constructor = $class->method('__construct');
            foreach ($constructor !== null ? ($constructor->stmts ?? []) : [] as $stmt) {
                if (! $stmt instanceof Stmt\Expression) {
                    continue;
                }
                $calls = [];
                $current = $stmt->expr;
                while ($current instanceof Expr\MethodCall) {
                    array_unshift($calls, $current);
                    $current = $current->var;
                }
                if (! $current instanceof Expr\Variable || $current->name !== 'this' || $calls === [] || Ast::callName($calls[0]) !== 'middleware') {
                    continue;
                }
                $applies = true;
                foreach (array_slice($calls, 1) as $modifier) {
                    $methods = Ast::stringArgs($modifier);
                    if (Ast::callName($modifier) === 'only' && ! in_array($method, $methods, true)) {
                        $applies = false;
                    }
                    if (Ast::callName($modifier) === 'except' && in_array($method, $methods, true)) {
                        $applies = false;
                    }
                }
                if ($applies) {
                    array_push($out, ...$this->normaliseAll($calls[0]));
                }
            }
        }

        return $out;
    }

    // ---------------------------------------------------------------- configuration

    /** bootstrap/app.php ->withMiddleware(function (Middleware $middleware) { ... }) */
    private function readBootstrapMiddleware(): void
    {
        $bootstrap = $this->project->file('bootstrap/app.php');
        if ($bootstrap === null) {
            return;
        }
        foreach (Ast::find($bootstrap->stmts(), fn (Node $n) => $n instanceof Expr\MethodCall) as $call) {
            /** @var Expr\MethodCall $call */
            $name = Ast::callName($call);
            if (! $call->var instanceof Expr\Variable) {
                continue; // only calls on the $middleware configurator
            }
            switch ($name) {
                case 'alias':
                    $this->readAliases(Ast::arg($call, 0, 'aliases'));
                    break;
                case 'web':
                case 'api':
                    foreach (['append' => 0, 'prepend' => 1] as $arg => $position) {
                        array_push($this->groups[$name], ...$this->normalise(Ast::arg($call, $position, $arg)));
                    }
                    $removed = $this->normalise(Ast::arg($call, 2, 'remove'));
                    $this->groups[$name] = array_values(array_diff($this->groups[$name], $removed));
                    if (in_array('csrf', $removed, true) && $name === 'web') {
                        $this->csrfExclusions[] = ['pattern' => '*', 'file' => $bootstrap->relativePath, 'line' => $call->getStartLine()];
                    }
                    break;
                case 'group':
                    $group = Ast::stringValue(Ast::arg($call, 0));
                    if ($group !== null) {
                        $this->groups[$group] = $this->normalise(Ast::arg($call, 1));
                    }
                    break;
                case 'appendtogroup':
                case 'prependtogroup':
                    $group = Ast::stringValue(Ast::arg($call, 0));
                    if ($group !== null) {
                        $this->groups[$group] = array_merge($this->groups[$group] ?? [], $this->normalise(Ast::arg($call, 1)));
                    }
                    break;
                case 'statefulapi':
                    $this->groups['api'][] = 'stateful';
                    break;
                case 'validatecsrftokens':
                    $this->readCsrfList(Ast::arg($call, 0, 'except'), $bootstrap);
                    break;
            }
        }
    }

    /** app/Http/Kernel.php (Laravel <= 10) */
    private function readHttpKernel(): void
    {
        $kernel = $this->project->classes()->get('App\\Http\\Kernel');
        if ($kernel === null) {
            return;
        }
        $groups = $kernel->propertyDefault('middlewareGroups');
        if ($groups instanceof Expr\Array_) {
            foreach ($groups->items as $item) {
                $group = $item !== null ? Ast::stringValue($item->key) : null;
                if ($group !== null) {
                    $this->groups[$group] = $this->normalise($item->value);
                }
            }
        }
        $this->readAliases($kernel->propertyDefault('middlewareAliases'));
        $this->readAliases($kernel->propertyDefault('routeMiddleware'));
    }

    private function readAliases(?Expr $array): void
    {
        if (! $array instanceof Expr\Array_) {
            return;
        }
        foreach ($array->items as $item) {
            $alias = Ast::stringValue($item->key);
            $class = Ast::stringValue($item->value);
            if ($alias === null || $class === null) {
                continue;
            }
            $known = self::CLASS_ALIASES[(string) Ast::shortName($class)] ?? null;
            // An alias pointing at a framework auth class behaves like that class; custom classes keep their alias.
            $this->aliases[$alias] = $known ?? $alias;
        }
    }

    /** app/Http/Middleware/VerifyCsrfToken.php protected $except = [...] (Laravel <= 10) */
    private function readCsrfMiddleware(): void
    {
        foreach ($this->project->classes()->all() as $class) {
            if (! in_array($class->shortName(), ['VerifyCsrfToken', 'ValidateCsrfToken'], true) || ! $class->hasProperty('except')) {
                continue;
            }
            $this->readCsrfList($class->propertyDefault('except'), $class->file);
        }
    }

    private function readCsrfList(?Expr $list, PhpFile $file): void
    {
        if (! $list instanceof Expr\Array_) {
            return;
        }
        foreach ($list->items as $item) {
            $pattern = Ast::stringValue($item->value);
            if ($pattern !== null) {
                $this->csrfExclusions[] = ['pattern' => $pattern, 'file' => $file->relativePath, 'line' => $item->getStartLine()];
            }
        }
    }
}
