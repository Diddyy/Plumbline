<?php

declare(strict_types=1);

namespace Plumbline\Analysis;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar;

/**
 * Decides whether an expression carries user input, given the current scope.
 *
 * Deliberately conservative in the "precision" direction: unknown functions and methods return
 * clean values. We would rather miss a flow than raise a finding we can't defend.
 */
final class Evaluator
{
    /** Request methods that return a single user-controlled value (subject to validation lookups). */
    private const INPUT_METHODS = [
        'input', 'get', 'query', 'post', 'string', 'str', 'header', 'cookie', 'route', 'server',
        'json', 'collect', 'fullurl', 'fullurlwithquery', 'url', 'path', 'getcontent', 'getrequesturi',
        'getquerystring', 'getpathinfo', 'useragent', 'bearertoken', 'decodedpath', 'segment', 'segments',
        'old', 'keys', 'only',
    ];

    /** Request methods that return the whole, unfiltered input bag. */
    private const BAG_METHODS = ['all', 'except', 'request', 'toarray'];

    /** Request methods whose result is user data that already passed validation. */
    private const VALIDATED_METHODS = ['validated', 'safe', 'validate', 'validatewithbag'];

    /** Methods that turn a tainted value into something harmless. */
    private const CLEANING_METHODS = [
        'tointeger', 'toint', 'tofloat', 'toboolean', 'tobool', 'isempty', 'isnotempty', 'count', 'length',
        'contains', 'containsall', 'startswith', 'endswith', 'exactly', 'is', 'isjson', 'isurl', 'isuuid',
        'isulid', 'ismatch', 'test', 'has', 'filled', 'missing', 'exists', 'integer', 'boolean', 'float',
        'date', 'enum', 'enums', 'slug', 'hash', 'hashname', 'getsize', 'getmimetype', 'extension', 'guessextension',
        'isvalid', 'store', 'storeas', 'storepublicly', 'storepubliclyas', 'path', 'getrealpath',
        'user', 'ip', 'ips', 'method', 'ismethod', 'ajax', 'pjax', 'wantsjson', 'expectsjson', 'secure',
        'routeis', 'fullurlis', 'file', 'hasfile', 'allfiles', 'session', 'fingerprint', 'boolean',
    ];

    /** Methods on a tainted bag that keep it a whole, unfiltered bag. */
    private const BAG_PRESERVING = ['all', 'toarray', 'except', 'merge', 'filter', 'collect', 'forget', 'replace'];

    /** Methods that return the client-supplied file name / type of an upload. */
    private const CLIENT_FILE_METHODS = ['getclientoriginalname', 'getclientoriginalextension', 'getclientmimetype'];

    /** Functions whose result carries the taint of their arguments. */
    private const PROPAGATORS = [
        'sprintf', 'vsprintf', 'implode', 'join', 'trim', 'ltrim', 'rtrim', 'strtolower', 'strtoupper', 'ucfirst',
        'lcfirst', 'ucwords', 'str_replace', 'str_ireplace', 'preg_replace', 'substr', 'mb_substr', 'str_pad',
        'strrev', 'nl2br', 'urldecode', 'rawurldecode', 'base64_decode', 'json_decode', 'html_entity_decode',
        'htmlspecialchars_decode', 'stripslashes', 'addslashes', 'array_values', 'array_merge', 'array_filter',
        'array_slice', 'array_unique', 'explode', 'str_repeat', 'wordwrap', 'strval', 'mb_strtolower',
        'mb_strtoupper', 'data_get', 'array_get', 'head', 'last', 'current', 'reset', 'end', 'array_pop',
        'array_shift', 'json_encode', 'serialize', 'http_build_query', 'collect', 'value', 'str', 'basename',
        'dirname', 'pathinfo', 'strip_tags', 'htmlspecialchars', 'htmlentities', 'e', 'mb_convert_case',
        'iconv', 'mb_convert_encoding', 'utf8_decode', 'utf8_encode', 'str_word_count', 'array_reverse',
        'array_combine', 'array_fill_keys', 'array_pad', 'array_replace', 'array_column', 'array_map',
        'iterator_to_array', 'gzuncompress', 'gzinflate', 'gzdecode', 'hex2bin', 'quotemeta', 'nl2br',
    ];

    /** Static helpers that pass their argument's taint through. */
    private const STATIC_PROPAGATORS = [
        'Str' => ['lower', 'upper', 'title', 'limit', 'words', 'replace', 'replacearray', 'replacefirst', 'replacelast',
            'substr', 'trim', 'ltrim', 'rtrim', 'finish', 'start', 'after', 'afterlast', 'before', 'beforelast', 'between',
            'betweenfirst', 'snake', 'camel', 'kebab', 'studly', 'squish', 'of', 'wrap', 'unwrap', 'remove', 'reverse',
            'padleft', 'padright', 'padboth', 'mask', 'apa', 'headline', 'ucfirst', 'lcfirst', 'markdown', 'inlinemarkdown'],
        'Arr' => ['get', 'first', 'last', 'only', 'except', 'flatten', 'wrap', 'pluck', 'join', 'string'],
    ];

    private const SUPERGLOBALS = ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES'];

    public function __construct(private readonly Scope $scope, private readonly FunctionContext $context)
    {
    }

    public function evaluate(?Node $expr): Value
    {
        if ($expr instanceof Node\Arg) {
            $expr = $expr->value;
        }

        return match (true) {
            // Must come before the generic Scalar arm: InterpolatedString extends Scalar.
            $expr instanceof Scalar\InterpolatedString => $this->interpolated($expr),

            $expr === null, $expr instanceof Scalar, $expr instanceof Expr\ConstFetch,
            $expr instanceof Expr\ClassConstFetch, $expr instanceof Expr\Closure,
            $expr instanceof Expr\ArrowFunction, $expr instanceof Expr\Isset_, $expr instanceof Expr\Empty_,
            $expr instanceof Expr\Instanceof_, $expr instanceof Expr\BooleanNot, $expr instanceof Expr\New_,
            $expr instanceof Expr\ShellExec => Value::clean(),

            $expr instanceof Expr\Variable => $this->variable($expr),
            $expr instanceof Expr\ArrayDimFetch => $this->dimFetch($expr),
            $expr instanceof Expr\PropertyFetch, $expr instanceof Expr\NullsafePropertyFetch => $this->propertyFetch($expr),
            $expr instanceof Expr\MethodCall, $expr instanceof Expr\NullsafeMethodCall => $this->methodCall($expr),
            $expr instanceof Expr\StaticCall => $this->staticCall($expr),
            $expr instanceof Expr\FuncCall => $this->funcCall($expr),
            $expr instanceof Expr\BinaryOp\Concat => Value::either($this->evaluate($expr->left), $this->evaluate($expr->right)),
            $expr instanceof Expr\BinaryOp\Coalesce => $this->coalesce($expr),
            $expr instanceof Expr\BinaryOp => Value::clean(),
            $expr instanceof Expr\Cast\Int_, $expr instanceof Expr\Cast\Double, $expr instanceof Expr\Cast\Bool_,
            $expr instanceof Expr\Cast\Unset_ => Value::clean(),
            $expr instanceof Expr\Cast => $this->evaluate($expr->expr)->withoutBag(),
            $expr instanceof Expr\Ternary => $this->ternary($expr),
            $expr instanceof Expr\Match_ => $this->match($expr),
            $expr instanceof Expr\Array_ => $this->array($expr),
            $expr instanceof Expr\Assign, $expr instanceof Expr\AssignRef => $this->evaluate($expr->expr),
            $expr instanceof Expr\AssignOp\Concat => Value::either($this->evaluate($expr->var), $this->evaluate($expr->expr)),
            $expr instanceof Expr\ErrorSuppress => $this->evaluate($expr->expr),
            default => Value::clean(),
        };
    }

    public function isTainted(?Node $expr): bool
    {
        return $this->evaluate($expr)->tainted;
    }

    private function interpolated(Scalar\InterpolatedString $expr): Value
    {
        $parts = array_filter($expr->parts, fn ($p) => ! $p instanceof Node\InterpolatedStringPart);

        return Value::either(...array_map(fn ($p) => $this->evaluate($p), array_values($parts)));
    }

    private function variable(Expr\Variable $expr): Value
    {
        if (! is_string($expr->name)) {
            return Value::clean();
        }
        if ($expr->name === 'this') {
            return $this->context->isFormRequest ? Value::request() : Value::clean();
        }
        if (in_array($expr->name, self::SUPERGLOBALS, true)) {
            return Value::tainted('$'.$expr->name, bag: true);
        }

        return $this->scope->get($expr->name) ?? Value::clean();
    }

    private function dimFetch(Expr\ArrayDimFetch $expr): Value
    {
        $key = Ast::stringValue($expr->dim);

        if ($expr->var instanceof Expr\Variable && $expr->var->name === '_SERVER') {
            $userControlled = $key !== null && (str_starts_with($key, 'HTTP_') || in_array($key, ['QUERY_STRING', 'REQUEST_URI', 'PHP_SELF', 'PATH_INFO'], true));

            return $userControlled ? Value::tainted('$_SERVER[\''.$key.'\']') : Value::clean();
        }

        $base = $this->evaluate($expr->var);
        if ($base->request) {
            return $this->scope->isValidatedSafe($key) ? Value::clean() : Value::tainted('$request[\''.$key.'\']');
        }
        if (! $base->tainted) {
            return Value::clean();
        }
        if ($this->scope->isValidatedSafe($key)) {
            return Value::clean();
        }

        return Value::tainted($base->source.($key !== null ? "['{$key}']" : '[...]'), validated: $base->validated);
    }

    private function propertyFetch(Expr\PropertyFetch|Expr\NullsafePropertyFetch $expr): Value
    {
        $name = $expr->name instanceof Node\Identifier ? $expr->name->toString() : null;

        if ($expr->var instanceof Expr\Variable && $expr->var->name === 'this') {
            if ($this->context->isLivewire && $name !== null && $this->context->isUserControlledProperty($name)) {
                return Value::tainted('Livewire public property $'.$name);
            }

            return Value::clean();
        }

        $base = $this->evaluate($expr->var);
        if ($base->request) {
            // $request->email is a magic input lookup.
            return $this->scope->isValidatedSafe($name) ? Value::clean() : Value::tainted('$request->'.$name);
        }

        return $base->tainted ? Value::tainted($base->source.'->'.$name) : Value::clean();
    }

    private function methodCall(Expr\MethodCall|Expr\NullsafeMethodCall $expr): Value
    {
        $method = Ast::callName($expr);
        if ($method === null) {
            return Value::clean();
        }

        if (in_array($method, self::CLIENT_FILE_METHODS, true)) {
            return Value::tainted('the client-supplied upload name ('.$method.'())');
        }

        $base = $this->evaluate($expr->var);
        if ($base->request) {
            return $this->requestMethod($method, $expr, '$request');
        }

        if (! $base->tainted || in_array($method, self::CLEANING_METHODS, true)) {
            return Value::clean();
        }

        if ($method === 'only') {
            return Value::tainted($base->source.'->only(...)');
        }

        return Value::tainted(
            $base->source,
            bag: $base->bag && in_array($method, self::BAG_PRESERVING, true),
            validated: $base->validated,
        );
    }

    private function staticCall(Expr\StaticCall $expr): Value
    {
        $method = Ast::callName($expr);
        $class = Ast::shortName(Ast::className($expr));
        if ($method === null || $class === null) {
            return Value::clean();
        }

        if (Ast::isFacade($expr, 'Request') || in_array($class, ['Input'], true)) {
            return $this->requestMethod($method, $expr, 'Request::');
        }

        $propagating = self::STATIC_PROPAGATORS[$class] ?? [];
        if (in_array($method, $propagating, true)) {
            return Value::either(...array_map(fn (Node\Arg $a) => $this->evaluate($a->value), Ast::args($expr)));
        }

        return Value::clean();
    }

    private function funcCall(Expr\FuncCall $expr): Value
    {
        $name = Ast::callName($expr);
        if ($name === null || $expr->isFirstClassCallable()) {
            return Value::clean();
        }

        switch ($name) {
            case 'request':
                $key = Ast::arg($expr, 0);
                if ($key === null) {
                    return Value::request();
                }
                $keyString = Ast::stringValue($key);

                return $this->scope->isValidatedSafe($keyString) ? Value::clean() : Value::tainted("request('{$keyString}')");
            case 'old':
                return Value::tainted("old('".Ast::stringValue(Ast::arg($expr, 0))."')");
            case 'filter_input':
            case 'getallheaders':
                return Value::tainted($name.'()');
            case 'file_get_contents':
                return Ast::stringValue(Ast::arg($expr, 0)) === 'php://input' ? Value::tainted("file_get_contents('php://input')") : Value::clean();
        }

        if (in_array($name, ['array_merge', 'array_replace', 'array_merge_recursive'], true)) {
            // array_merge($request->all(), [...]) is still the whole, unfiltered bag.
            foreach (Ast::args($expr) as $arg) {
                $value = $this->evaluate($arg->value);
                if ($value->bag) {
                    return $value;
                }
            }
        }

        if (in_array($name, self::PROPAGATORS, true)) {
            return Value::either(...array_map(fn (Node\Arg $a) => $this->evaluate($a->value), Ast::args($expr)));
        }

        return Value::clean();
    }

    private function requestMethod(string $method, Expr\CallLike $call, string $prefix): Value
    {
        $key = Ast::stringValue(Ast::arg($call, 0));
        $hasArgs = ! $call->isFirstClassCallable() && Ast::args($call) !== [];
        $label = $prefix.($prefix === '$request' ? '->' : '').$method."(".($key !== null ? "'{$key}'" : '').')';

        if (in_array($method, self::BAG_METHODS, true)) {
            return Value::tainted($label, bag: true);
        }
        if (in_array($method, self::VALIDATED_METHODS, true)) {
            if ($key !== null && $this->scope->isValidatedSafe($key)) {
                return Value::clean();
            }

            return Value::tainted($label, validated: true);
        }
        if (in_array($method, ['input', 'post', 'query', 'json', 'collect'], true) && ! $hasArgs) {
            return Value::tainted($label, bag: true);
        }
        if (in_array($method, self::INPUT_METHODS, true)) {
            return $this->scope->isValidatedSafe($key) ? Value::clean() : Value::tainted($label);
        }

        return Value::clean();
    }

    private function coalesce(Expr\BinaryOp\Coalesce $expr): Value
    {
        return Value::either($this->evaluate($expr->left), $this->evaluate($expr->right));
    }

    private function ternary(Expr\Ternary $expr): Value
    {
        // in_array($x, ALLOWED) ? $x : 'default'  — an allowlist, the result is safe.
        if ($expr->cond instanceof Expr\FuncCall && Ast::callName($expr->cond) === 'in_array') {
            return Value::clean();
        }

        return Value::either($expr->if === null ? $this->evaluate($expr->cond) : $this->evaluate($expr->if), $this->evaluate($expr->else));
    }

    private function match(Expr\Match_ $expr): Value
    {
        return Value::either(...array_map(fn (Node\MatchArm $arm) => $this->evaluate($arm->body), $expr->arms));
    }

    private function array(Expr\Array_ $expr): Value
    {
        $values = [];
        foreach ($expr->items as $item) {
            if ($item !== null) {
                $values[] = $this->evaluate($item->value);
            }
        }

        return Value::either(...$values);
    }
}
