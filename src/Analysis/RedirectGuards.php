<?php

declare(strict_types=1);

namespace Plumbline\Analysis;

use PhpParser\Node;
use PhpParser\Node\Expr;

/**
 * Recognises conditions that pin a URL to this site:
 *   str_starts_with($url, '/players/'), Str::startsWith($url, config('app.url')),
 *   parse_url($url, PHP_URL_HOST) === $request->getHost()
 */
final class RedirectGuards
{
    /**
     * Variables a (positive) condition proves to be same-origin. Only conjunctions count:
     * `$a && str_starts_with($url, '/')` proves it, `$a || ...` does not.
     *
     * @return list<string>
     */
    public static function checkedVars(?Expr $cond): array
    {
        if ($cond instanceof Expr\BinaryOp\BooleanAnd || $cond instanceof Expr\BinaryOp\LogicalAnd) {
            return array_merge(self::checkedVars($cond->left), self::checkedVars($cond->right));
        }

        // parse_url($url, PHP_URL_HOST) === ... / in_array(parse_url($url, PHP_URL_HOST), [...])
        if ($cond instanceof Expr\BinaryOp\Identical || $cond instanceof Expr\BinaryOp\Equal || $cond instanceof Expr\FuncCall) {
            $out = [];
            foreach (Ast::find($cond, fn (Node $n) => $n instanceof Expr\FuncCall && Ast::callName($n) === 'parse_url') as $call) {
                /** @var Expr\FuncCall $call */
                $name = Ast::varName(Ast::arg($call, 0));
                if ($name !== null) {
                    $out[] = $name;
                }
            }
            if ($out !== []) {
                return $out;
            }
        }

        $haystack = null;
        $needle = null;
        if ($cond instanceof Expr\FuncCall && Ast::callName($cond) === 'str_starts_with') {
            [$haystack, $needle] = [Ast::arg($cond, 0, 'haystack'), Ast::arg($cond, 1, 'needle')];
        } elseif ($cond instanceof Expr\StaticCall && Ast::shortName(Ast::className($cond)) === 'Str' && Ast::callName($cond) === 'startswith') {
            [$haystack, $needle] = [Ast::arg($cond, 0, 'haystack'), Ast::arg($cond, 1, 'needles')];
        }
        $name = Ast::varName($haystack);

        return $name !== null && self::isSameOriginPrefix($needle) ? [$name] : [];
    }

    private static function isSameOriginPrefix(?Expr $needle): bool
    {
        if ($needle instanceof Expr\Array_) {
            foreach ($needle->items as $item) {
                if (! self::isSameOriginPrefix($item->value)) {
                    return false;
                }
            }

            return $needle->items !== [];
        }
        $literal = Ast::stringValue($needle);
        if ($literal !== null) {
            // '/' alone would still allow '//evil.com'.
            return str_starts_with($literal, '/') && strlen($literal) > 1 && ! str_starts_with($literal, '//') && ! str_starts_with($literal, '/\\');
        }
        if ($needle instanceof Expr\FuncCall) {
            return in_array(Ast::callName($needle), ['url', 'config', 'route', 'secure_url', 'env'], true);
        }
        if ($needle instanceof Expr\MethodCall) {
            return in_array(Ast::callName($needle), ['getschemeandhttphost', 'root', 'gethost', 'to'], true);
        }

        return false;
    }
}
