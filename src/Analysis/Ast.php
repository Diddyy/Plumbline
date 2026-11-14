<?php

declare(strict_types=1);

namespace Plumbline\Analysis;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Name;

/** Small, dependency-free helpers for reading php-parser nodes. */
final class Ast
{
    /** Lower-cased name of a called function or method, or null when dynamic. */
    public static function callName(Node $node): ?string
    {
        if ($node instanceof Expr\FuncCall) {
            return $node->name instanceof Name ? strtolower(self::nameString($node->name)) : null;
        }

        if ($node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall || $node instanceof Expr\StaticCall) {
            return $node->name instanceof Node\Identifier ? strtolower($node->name->toString()) : null;
        }

        return null;
    }

    /** The resolved (fully-qualified) name, falling back to the written name. */
    public static function nameString(Name $name): string
    {
        // Unqualified function calls only get a "namespacedName" (ambiguous); we keep their
        // written name so `exec()` inside a namespace is still `exec`.
        $resolved = $name->getAttribute('resolvedName');

        return $resolved instanceof Name ? $resolved->toString() : $name->toString();
    }

    /** Resolved class name of a static call / new / class constant fetch. */
    public static function className(Node $node): ?string
    {
        $class = match (true) {
            $node instanceof Expr\StaticCall,
            $node instanceof Expr\ClassConstFetch,
            $node instanceof Expr\StaticPropertyFetch,
            $node instanceof Expr\New_ => $node->class,
            default => null,
        };

        return $class instanceof Name ? self::nameString($class) : null;
    }

    /** Last segment of a class name: Illuminate\Support\Facades\DB -> DB */
    public static function shortName(?string $class): ?string
    {
        if ($class === null) {
            return null;
        }
        $pos = strrpos($class, '\\');

        return $pos === false ? $class : substr($class, $pos + 1);
    }

    /** True when a static call targets the given facade, aliased or imported. */
    public static function isFacade(Expr\StaticCall $call, string $facade): bool
    {
        $class = self::className($call);

        return $class !== null && (
            strcasecmp($class, $facade) === 0
            || strcasecmp($class, 'Illuminate\\Support\\Facades\\'.$facade) === 0
        );
    }

    /** Literal string value of String_ or Foo::class, else null. */
    public static function stringValue(?Node $node): ?string
    {
        if ($node instanceof Node\Arg) {
            $node = $node->value;
        }
        if ($node instanceof Node\Scalar\String_) {
            return $node->value;
        }
        if ($node instanceof Expr\ClassConstFetch
            && $node->name instanceof Node\Identifier
            && strtolower($node->name->toString()) === 'class') {
            return self::className($node);
        }

        return null;
    }

    /**
     * Strings from a literal string or literal array of strings ("auth" or ["auth", "verified"]).
     *
     * @return list<string>
     */
    public static function stringList(?Node $node): array
    {
        if ($node instanceof Node\Arg) {
            $node = $node->value;
        }
        $single = self::stringValue($node);
        if ($single !== null) {
            return [$single];
        }
        $out = [];
        if ($node instanceof Expr\Array_) {
            foreach ($node->items as $item) {
                if ($item === null) {
                    continue;
                }
                $value = self::stringValue($item->value);
                if ($value !== null) {
                    $out[] = $value;
                }
            }
        }

        return $out;
    }

    /**
     * All string args of a call, flattened ("auth", ["a","b"] -> auth, a, b).
     *
     * @return list<string>
     */
    public static function stringArgs(Expr\CallLike $call): array
    {
        if ($call->isFirstClassCallable()) {
            return [];
        }
        $out = [];
        foreach (self::args($call) as $arg) {
            array_push($out, ...self::stringList($arg->value));
        }

        return $out;
    }

    /**
     * Real arguments of a call. Unlike getArgs(), safe for first-class callables (foo(...)) and
     * PHP 8.5 partial applications (foo($x, ?)), whose placeholders are skipped.
     *
     * @return list<Node\Arg>
     */
    public static function args(Expr\CallLike $call): array
    {
        return array_values(array_filter($call->getRawArgs(), fn ($arg) => $arg instanceof Node\Arg));
    }

    /** The Nth positional argument, or a named argument. */
    public static function arg(Expr\CallLike $call, int $position, ?string $name = null): ?Expr
    {
        if ($call->isFirstClassCallable()) {
            return null;
        }
        $positional = 0;
        foreach (self::args($call) as $arg) {
            if ($arg->name !== null) {
                if ($name !== null && $arg->name->toString() === $name) {
                    return $arg->value;
                }
                continue;
            }
            if ($positional === $position) {
                return $arg->value;
            }
            $positional++;
        }

        return null;
    }

    /** Variable name for $foo, or null for dynamic variables. */
    public static function varName(?Node $node): ?string
    {
        return $node instanceof Expr\Variable && is_string($node->name) ? $node->name : null;
    }

    /**
     * Resolved type names of a parameter/property type (nullable and unions flattened).
     *
     * @return list<string>
     */
    public static function typeNames(?Node $type): array
    {
        if ($type === null) {
            return [];
        }
        if ($type instanceof Node\NullableType) {
            return self::typeNames($type->type);
        }
        if ($type instanceof Node\UnionType || $type instanceof Node\IntersectionType) {
            $out = [];
            foreach ($type->types as $inner) {
                array_push($out, ...self::typeNames($inner));
            }

            return $out;
        }
        if ($type instanceof Name) {
            return [self::nameString($type)];
        }
        if ($type instanceof Node\Identifier) {
            return [strtolower($type->toString())];
        }

        return [];
    }

    /**
     * Attribute class names on a node (classes, methods, properties).
     *
     * @return list<string>
     */
    public static function attributeNames(Node $node): array
    {
        $groups = property_exists($node, 'attrGroups') ? $node->attrGroups : [];
        $out = [];
        foreach ($groups as $group) {
            foreach ($group->attrs as $attr) {
                $out[] = self::nameString($attr->name);
            }
        }

        return $out;
    }

    /**
     * Visit the given nodes and every descendant (depth-first, source order).
     *
     * @param Node|list<Node>|null $nodes
     * @param callable(Node): void $visit
     */
    public static function walk(Node|array|null $nodes, callable $visit): void
    {
        if ($nodes === null) {
            return;
        }
        foreach (is_array($nodes) ? $nodes : [$nodes] as $node) {
            if (! $node instanceof Node) {
                continue;
            }
            $visit($node);
            foreach ($node->getSubNodeNames() as $name) {
                $child = $node->$name;
                if ($child instanceof Node) {
                    self::walk($child, $visit);
                } elseif (is_array($child)) {
                    self::walk(array_values(array_filter($child, fn ($c) => $c instanceof Node)), $visit);
                }
            }
        }
    }

    /**
     * Find all descendants matching a predicate.
     *
     * @param Node|list<Node>|null $nodes
     * @param callable(Node): bool $predicate
     * @return list<Node>
     */
    public static function find(Node|array|null $nodes, callable $predicate): array
    {
        $out = [];
        self::walk($nodes, function (Node $node) use ($predicate, &$out): void {
            if ($predicate($node)) {
                $out[] = $node;
            }
        });

        return $out;
    }

    /**
     * True for conditions that only hold outside production:
     * app()->environment('local'), App::isLocal(), $this->app->runningUnitTests(), config('app.env') === 'local'.
     */
    public static function isLocalOnlyCondition(?Node $cond): bool
    {
        $local = ['local', 'testing', 'dev', 'development'];
        if ($cond instanceof Expr\BinaryOp\BooleanAnd || $cond instanceof Expr\BinaryOp\LogicalAnd) {
            return self::isLocalOnlyCondition($cond->left) || self::isLocalOnlyCondition($cond->right);
        }
        if ($cond instanceof Expr\BinaryOp\Identical || $cond instanceof Expr\BinaryOp\Equal) {
            foreach ([[$cond->left, $cond->right], [$cond->right, $cond->left]] as [$a, $b]) {
                if ($a instanceof Expr\FuncCall && in_array(self::callName($a), ['config', 'env'], true)
                    && in_array(self::stringValue(self::arg($a, 0)), ['app.env', 'APP_ENV'], true)
                    && in_array(self::stringValue($b), $local, true)) {
                    return true;
                }
            }

            return false;
        }
        if (! $cond instanceof Expr\MethodCall && ! $cond instanceof Expr\StaticCall) {
            return false;
        }
        $method = self::callName($cond);
        if (in_array($method, ['islocal', 'runningunittests'], true)) {
            return true;
        }
        if ($method !== 'environment') {
            return false;
        }
        $envs = self::stringArgs($cond);

        return $envs !== [] && array_diff($envs, $local) === [];
    }

    /**
     * Snake/camel-case aware word split: "resetPasswordToken" -> [reset, password, token].
     *
     * @return list<string>
     */
    public static function words(string $identifier): array
    {
        $spaced = preg_replace('/([a-z0-9])([A-Z])/', '$1 $2', $identifier) ?? $identifier;
        $parts = preg_split('/[^A-Za-z0-9]+/', strtolower($spaced)) ?: [];

        return array_values(array_filter($parts, fn (string $p) => $p !== ''));
    }

    /** A human-ish name for the "thing" an expression refers to: $foo, $this->foo, $data['foo'], foo(). */
    public static function subjectName(?Node $node): ?string
    {
        return match (true) {
            $node instanceof Expr\Variable => is_string($node->name) ? $node->name : null,
            $node instanceof Expr\PropertyFetch, $node instanceof Expr\NullsafePropertyFetch,
            $node instanceof Expr\StaticPropertyFetch => $node->name instanceof Node\Identifier
                ? $node->name->toString() : null,
            $node instanceof Expr\ArrayDimFetch => self::stringValue($node->dim) ?? self::subjectName($node->var),
            $node instanceof Expr\MethodCall => self::stringValue(self::arg($node, 0)) ?? ($node->name instanceof Node\Identifier ? $node->name->toString() : null),
            default => null,
        };
    }
}
