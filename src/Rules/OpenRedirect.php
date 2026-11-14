<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Plumbline\Analysis\Ast;
use Plumbline\Analysis\Evaluator;
use Plumbline\Analysis\RedirectGuards;
use Plumbline\Analysis\FunctionContext;
use Plumbline\Analysis\Scope;
use Plumbline\Severity;

final class OpenRedirect implements TaintRule
{
    public function meta(): RuleMeta
    {
        return new RuleMeta(
            'REDIR-001',
            'open-redirect',
            'Redirect to a user-supplied URL',
            Severity::Medium,
            'The redirect target comes from the request, so a link to your site can bounce visitors to any other site.',
            'CWE-601',
        );
    }

    public function inspect(Node $node, Scope $scope, FunctionContext $context): iterable
    {
        $target = $this->target($node);
        if ($target === null) {
            return;
        }

        $value = (new Evaluator($scope, $context))->evaluate($target);
        // The current request's own URL is same-origin; redirecting back to it is fine.
        if (! $value->tainted || preg_match('/(->|::)(fullurl|fullurlwithquery|url|path|decodedpath)\(/i', $value->source)) {
            return;
        }
        if ($this->isSameOriginChecked($target, $scope) || $this->startsWithLocalPath($this->resolve($target, $node, $context), $value->source)
            || $this->parsesTarget($target, $context)) {
            return;
        }

        yield $context->finding($this->meta(), $node, "The redirect target comes from {$value->source}. Redirect to a named route, or only accept relative paths (and reject '//').");
    }

    /** Inside `if (str_starts_with($url, '/x/'))`, or after `abort_unless(...)` / an early return on the same check. */
    private function isSameOriginChecked(Expr $target, Scope $scope): bool
    {
        $checked = [];
        foreach ($scope->guards() as $guard) {
            array_push($checked, ...RedirectGuards::checkedVars($guard));
        }
        foreach (Ast::find($target, fn (Node $n) => $n instanceof Expr\Variable && is_string($n->name)) as $variable) {
            /** @var Expr\Variable $variable */
            $name = (string) $variable->name;
            if ($scope->isPrefixChecked($name) || in_array($name, $checked, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * redirect('/posts/'.$id) stays on this host: Laravel prefixes relative paths with the app URL, and
     * only targets starting with '//' or a scheme leave the site. A bare '/' prefix is safe only for route
     * parameters, which can't contain '/'.
     *
     * route('index').$from is NOT safe: 'https://host' + '@evil.com' points at evil.com.
     */
    private function startsWithLocalPath(Expr $target, string $source): bool
    {
        $parts = $this->leadingParts($target);
        $first = $parts[0] ?? null;
        $prefix = null;
        if ($first instanceof Node\Scalar\String_) {
            $prefix = $first->value;
        } elseif ($first instanceof Node\InterpolatedStringPart) {
            $prefix = $first->value;
        } elseif ($first instanceof Expr\FuncCall && in_array(Ast::callName($first), ['url', 'route', 'secure_url'], true)) {
            // Absolute same-origin URL: safe only when a path separator follows it.
            $next = $parts[1] ?? null;
            $nextValue = $next instanceof Node\Scalar\String_ || $next instanceof Node\InterpolatedStringPart ? $next->value : '';

            return str_starts_with($nextValue, '/') || str_starts_with($nextValue, '?') || str_starts_with($nextValue, '#');
        }
        // "https://www.dropbox.com/oauth2/authorize?client_id=$key": the host is fixed.
        if ($prefix !== null && preg_match('#^[a-z][a-z0-9+.\-]*://[^/?\#@\\\\]+[/?\#]#i', $prefix)) {
            return true;
        }
        if ($prefix === null || ! str_starts_with($prefix, '/') || str_starts_with($prefix, '//') || str_starts_with($prefix, '/\\')) {
            return false;
        }

        return strlen($prefix) > 1 || str_starts_with($source, 'route parameter');
    }

    /** $url = 'app://confirm/'.$token; redirect()->away($url) — look at what $url was last set to. */
    private function resolve(Expr $target, Node $sink, FunctionContext $context): Expr
    {
        $name = Ast::varName($target);
        if ($name === null || $context->function === null) {
            return $target;
        }
        $resolved = $target;
        foreach (Ast::find($context->function, fn (Node $n) => $n instanceof Expr\Assign && Ast::varName($n->var) === $name) as $assign) {
            /** @var Expr\Assign $assign */
            if ($assign->getStartLine() <= $sink->getStartLine()) {
                $resolved = $assign->expr;
            }
        }

        return $resolved;
    }

    /** The function runs parse_url() on the redirect variable: it is inspecting the host. */
    private function parsesTarget(Expr $target, FunctionContext $context): bool
    {
        $names = array_map(fn (Node $v) => Ast::varName($v), Ast::find($target, fn (Node $n) => $n instanceof Expr\Variable && is_string($n->name)));
        if ($names === [] || $context->function === null) {
            return false;
        }

        return Ast::find($context->function, fn (Node $n) => $n instanceof Expr\FuncCall && Ast::callName($n) === 'parse_url'
            && in_array(Ast::varName(Ast::arg($n, 0)), $names, true)) !== [];
    }

    /** @return list<Node> the left-to-right pieces of a concatenation or interpolated string */
    private function leadingParts(Expr $expr): array
    {
        if ($expr instanceof Expr\BinaryOp\Concat) {
            return array_merge($this->leadingParts($expr->left), $this->leadingParts($expr->right));
        }
        if ($expr instanceof Node\Scalar\InterpolatedString) {
            return $expr->parts;
        }

        return [$expr];
    }

    private function target(Node $node): ?Expr
    {
        // redirect($url)
        if ($node instanceof Expr\FuncCall && Ast::callName($node) === 'redirect') {
            return Ast::arg($node, 0, 'to');
        }

        if ($node instanceof Expr\MethodCall && in_array(Ast::callName($node), ['to', 'away', 'redirectto'], true)) {
            $var = $node->var;
            $isRedirector = ($var instanceof Expr\FuncCall && in_array(Ast::callName($var), ['redirect', 'response'], true) && Ast::arg($var, 0) === null);

            return $isRedirector ? Ast::arg($node, 0, 'path') : null;
        }

        // Redirect::to($url), Redirect::away($url)
        if ($node instanceof Expr\StaticCall && Ast::isFacade($node, 'Redirect') && in_array(Ast::callName($node), ['to', 'away'], true)) {
            return Ast::arg($node, 0, 'path');
        }

        return null;
    }
}
