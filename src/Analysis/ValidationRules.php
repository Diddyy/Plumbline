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
        if (! $array instanceof Expr\Array_) {
            return [];
        }
        $out = [];
        foreach ($array->items as $item) {
            if ($item === null) {
                continue;
            }
            $key = Ast::stringValue($item->key);
            if ($key === null) {
                continue;
            }
            $out[$key] = self::isSafe($item->value);
        }

        return $out;
    }

    /** @return array<string, bool> */
    public static function fromFormRequest(ClassInfo $class): array
    {
        $rules = $class->method('rules');
        if ($rules === null) {
            return [];
        }
        $out = [];
        foreach (Ast::find($rules->stmts ?? [], fn (Node $n) => $n instanceof Node\Stmt\Return_) as $return) {
            /** @var Node\Stmt\Return_ $return */
            $out += self::fromArray($return->expr);
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
