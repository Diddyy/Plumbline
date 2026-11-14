<?php

declare(strict_types=1);

namespace Plumbline\Analysis;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Plumbline\Project\ClassInfo;

/**
 * Reads Laravel validation rule arrays and decides, per input key, whether the rules constrain the
 * value to something that cannot carry an injection payload (an integer, a UUID, one of a fixed set...).
 */
final class ValidationRules
{
    private const SAFE_STRING_RULES = [
        'integer', 'int', 'numeric', 'boolean', 'bool', 'uuid', 'ulid', 'digits', 'digits_between',
        'date', 'date_format', 'in', 'exists', 'alpha', 'alpha_num', 'alpha_dash', 'hex_color',
        'mac_address', 'ip', 'ipv4', 'ipv6', 'decimal', 'accepted', 'declined', 'enum', 'timezone',
    ];

    private const SAFE_RULE_CLASSES = ['In', 'Enum', 'Exists'];

    private const SAFE_RULE_FACTORIES = ['in', 'enum', 'exists', 'date', 'numeric', 'integer'];

    /**
     * @return array<string, bool> key => safe
     */
    public static function fromArray(?Node $array): array
    {
        return array_map(fn (Expr $rules) => self::isSafe($rules), self::ruleExpressions($array));
    }

    /**
     * Keys validated by a custom rule object (new IsValidOriginUrl(), a closure). We can't read the
     * rule, but the developer wrote a check for exactly this field; value-shape rules (redirects)
     * treat that as handled.
     *
     * @return list<string>
     */
    public static function customRuleKeys(?Node $array): array
    {
        return self::customKeysOf(self::ruleExpressions($array));
    }

    /** @return array<string, bool> */
    public static function fromFormRequest(ClassInfo $class): array
    {
        return array_map(fn (Expr $rules) => self::isSafe($rules), self::formRequestRules($class));
    }

    /** @return list<string> */
    public static function customRuleKeysFromFormRequest(ClassInfo $class): array
    {
        return self::customKeysOf(self::formRequestRules($class));
    }

    /**
     * key => rules expression, from `return [...]` or `$rules = [...]; $rules['x'] = ...; return $rules;`
     *
     * @return array<string, Expr>
     */
    private static function formRequestRules(ClassInfo $class): array
    {
        $method = $class->method('rules');
        if ($method === null) {
            return [];
        }
        $stmts = $method->stmts ?? [];
        $out = [];
        foreach (Ast::find($stmts, fn (Node $n) => $n instanceof Node\Stmt\Return_) as $return) {
            /** @var Node\Stmt\Return_ $return */
            $out += self::ruleExpressions($return->expr);
            $variable = Ast::varName($return->expr);
            if ($variable === null) {
                continue;
            }
            foreach (Ast::find($stmts, fn (Node $n) => $n instanceof Expr\Assign) as $assign) {
                /** @var Expr\Assign $assign */
                if (Ast::varName($assign->var) === $variable) {
                    $out += self::ruleExpressions($assign->expr);
                } elseif ($assign->var instanceof Expr\ArrayDimFetch && Ast::varName($assign->var->var) === $variable) {
                    $key = Ast::stringValue($assign->var->dim);
                    if ($key !== null) {
                        $out[$key] = $assign->expr;
                    }
                }
            }
        }

        return $out;
    }

    /** @return array<string, Expr> */
    private static function ruleExpressions(?Node $array): array
    {
        if (! $array instanceof Expr\Array_) {
            return [];
        }
        $out = [];
        foreach ($array->items as $item) {
            $key = Ast::stringValue($item->key);
            if ($key !== null) {
                $out[$key] = $item->value;
            }
        }

        return $out;
    }

    /**
     * @param array<string, Expr> $rules
     * @return list<string>
     */
    private static function customKeysOf(array $rules): array
    {
        $out = [];
        foreach ($rules as $key => $expr) {
            $custom = Ast::find($expr, fn (Node $n) => ($n instanceof Expr\New_ && ! in_array(Ast::shortName(Ast::className($n)), ['In', 'Enum', 'Exists', 'Unique', 'Password', 'File', 'ImageFile', 'Dimensions'], true))
                || $n instanceof Expr\Closure || $n instanceof Expr\ArrowFunction);
            if ($custom !== []) {
                $out[] = $key;
            }
        }

        return $out;
    }

    private static function isSafe(Expr $rules): bool
    {
        $string = Ast::stringValue($rules);
        if ($string !== null) {
            return self::stringIsSafe($string);
        }
        if (! $rules instanceof Expr\Array_) {
            return false;
        }
        foreach ($rules->items as $item) {
            if ($item === null) {
                continue;
            }
            $value = $item->value;
            $string = Ast::stringValue($value);
            if ($string !== null && self::stringIsSafe($string)) {
                return true;
            }
            if ($value instanceof Expr\New_ && in_array(Ast::shortName(Ast::className($value)), self::SAFE_RULE_CLASSES, true)) {
                return true;
            }
            if ($value instanceof Expr\StaticCall && Ast::shortName(Ast::className($value)) === 'Rule'
                && in_array(Ast::callName($value), self::SAFE_RULE_FACTORIES, true)) {
                return true;
            }
        }

        return false;
    }

    private static function stringIsSafe(string $rules): bool
    {
        foreach (explode('|', $rules) as $rule) {
            $name = strtolower(trim(explode(':', $rule, 2)[0]));
            if (in_array($name, self::SAFE_STRING_RULES, true)) {
                return true;
            }
        }

        return false;
    }
}
