<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar;
use Plumbline\Analysis\Ast;
use Plumbline\Analysis\Evaluator;
use Plumbline\Analysis\FunctionContext;
use Plumbline\Analysis\Scope;
use Plumbline\Severity;

/**
 * Storing an upload under a client-chosen name lets the client choose the extension: shell.php,
 * page.html or image.svg can then be executed or served as active content from your domain.
 *
 * Names that end in a server-chosen extension ($file->extension(), '.jpg') are not reported.
 */
final class UnsafeUploadName implements TaintRule
{
    public function meta(): RuleMeta
    {
        return new RuleMeta(
            'UPLOAD-001',
            'client-controlled-upload-name',
            'Upload stored publicly under a client-chosen file name',
            Severity::High,
            'The stored file name (and so its extension) comes from the client.',
            'CWE-434',
        );
    }

    public function inspect(Node $node, Scope $scope, FunctionContext $context): iterable
    {
        $sink = $this->sink($node);
        if ($sink === null) {
            return;
        }
        [$name, $label, $public] = $sink;
        if ($name === null || $this->endsWithServerExtension($name)) {
            return;
        }

        $value = (new Evaluator($scope, $context))->evaluate($name);
        if (! $value->tainted) {
            return;
        }
        // move() is a common method name; only treat it as an upload sink when it clearly is one.
        if ($label === 'move()' && ! str_contains($value->source, 'upload name') && ! $this->receiverIsUpload($node)) {
            return;
        }
        // Private storage isn't served by the web server, and an allowlisted extension can't be .php.
        if ($this->isPrivate($node) || $this->hasExtensionAllowlist($context)) {
            return;
        }

        // A client-chosen extension only matters where the web server serves the file.
        if (! $public) {
            return;
        }

        yield $context->finding(
            $this->meta(),
            $node,
            "{$label} stores the upload in public storage under a name from {$value->source}, so the client picks the extension (.php, .html, .svg) of a file your server will serve. Use \$file->hashName(), or Str::uuid().'.'.\$file->extension().",
        );
    }

    /** @return array{0: ?Expr, 1: string, 2: bool}|null  [name expression, label, stored publicly] */
    private function sink(Node $node): ?array
    {
        if (! $node instanceof Expr\MethodCall && ! $node instanceof Expr\StaticCall) {
            return null;
        }
        $method = Ast::callName($node);

        return match ($method) {
            // $file->storeAs('avatars', $name, 'public') / ->storePubliclyAs(...)
            'storeas' => [Ast::arg($node, 1, 'name') ?? Ast::arg($node, 0, 'path'), 'storeAs()', $this->isPublicDisk(Ast::arg($node, 2, 'options'))],
            'storepubliclyas' => [Ast::arg($node, 1, 'name') ?? Ast::arg($node, 0, 'path'), 'storePubliclyAs()', true],
            // $file->move(public_path('uploads'), $name)
            'move' => $node instanceof Expr\MethodCall && Ast::arg($node, 1, 'name') !== null
                ? [Ast::arg($node, 1, 'name'), 'move()', $this->mentionsPublicPath(Ast::arg($node, 0, 'directory'))]
                : null,
            // Storage::putFileAs('avatars', $file, $name)
            'putfileas' => [Ast::arg($node, 2, 'name'), 'putFileAs()', $this->onPublicDisk($node) || $this->isPublicDisk(Ast::arg($node, 3, 'options'))],
            default => null,
        };
    }

    private function endsWithServerExtension(Expr $expr): bool
    {
        $last = $expr;
        while ($last instanceof Expr\BinaryOp\Concat) {
            $last = $last->right;
        }
        if ($last instanceof Scalar\InterpolatedString) {
            $parts = $last->parts;
            $last = end($parts) ?: null;
            if ($last instanceof Node\InterpolatedStringPart) {
                return str_contains($last->value, '.');
            }
        }
        if ($last instanceof Scalar\String_) {
            return str_contains($last->value, '.');
        }

        return ($last instanceof Expr\MethodCall || $last instanceof Expr\NullsafeMethodCall)
            && in_array(Ast::callName($last), ['extension', 'guessextension', 'hashname'], true);
    }

    /** putFileAs($dir, $file, $name, 'private') / storeAs($dir, $name, ['visibility' => 'private']) */
    private function isPrivate(Node $node): bool
    {
        if (! $node instanceof Expr\CallLike || $node->isFirstClassCallable()) {
            return false;
        }
        foreach (Ast::args($node) as $arg) {
            if (Ast::stringValue($arg->value) === 'private') {
                return true;
            }
            if ($arg->value instanceof Expr\Array_) {
                foreach ($arg->value->items as $item) {
                    if (Ast::stringValue($item->key) === 'visibility' && Ast::stringValue($item->value) === 'private') {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * The client's extension is checked somewhere we can see: an `extensions:` validation rule, an
     * in_array() allowlist of getClientOriginalExtension(), here or in a same-class helper.
     */
    private function hasExtensionAllowlist(FunctionContext $context): bool
    {
        $bodies = [];
        if ($context->function !== null) {
            $bodies[] = $context->function;
        }
        if ($context->class !== null && $context->function !== null) {
            foreach (Ast::find($context->function, fn (Node $n) => $n instanceof Expr\MethodCall && $n->var instanceof Expr\Variable && $n->var->name === 'this') as $call) {
                /** @var Expr\MethodCall $call */
                $helper = $call->name instanceof Node\Identifier ? $context->class->method($call->name->toString()) : null;
                if ($helper !== null && $helper !== $context->function) {
                    $bodies[] = $helper;
                }
            }
        }
        foreach ($context->function?->getParams() ?? [] as $param) {
            foreach (Ast::typeNames($param->type) as $type) {
                $rules = $context->project->classes()->get($type)?->method('rules');
                if ($rules !== null) {
                    $bodies[] = $rules;
                }
            }
        }

        foreach ($bodies as $body) {
            $found = Ast::find($body, function (Node $n): bool {
                if ($n instanceof Node\Scalar\String_) {
                    return (bool) preg_match('/(^|\|)extensions:/', $n->value);
                }
                if (($n instanceof Expr\MethodCall || $n instanceof Expr\StaticCall) && Ast::callName($n) === 'extensions') {
                    return true; // File::types([...])->extensions([...])
                }

                return $n instanceof Expr\FuncCall && Ast::callName($n) === 'in_array'
                    && Ast::find($n, fn (Node $m) => in_array(Ast::callName($m), ['getclientoriginalextension', 'extension'], true)
                        || ($m instanceof Expr\Variable && is_string($m->name) && in_array(array_slice(Ast::words($m->name), -1)[0] ?? '', ['ext', 'extension'], true))) !== [];
            });
            if ($found !== []) {
                return true;
            }
        }

        return false;
    }

    private function receiverIsUpload(Node $node): bool
    {
        $var = $node instanceof Expr\MethodCall ? $node->var : null;

        return ($var instanceof Expr\MethodCall || $var instanceof Expr\FuncCall) && Ast::callName($var) === 'file';
    }

    private function isPublicDisk(?Expr $options): bool
    {
        if (Ast::stringValue($options) === 'public') {
            return true;
        }
        if ($options instanceof Expr\Array_) {
            foreach ($options->items as $item) {
                $key = Ast::stringValue($item->key);
                if (($key === 'disk' || $key === 'visibility') && Ast::stringValue($item->value) === 'public') {
                    return true;
                }
            }
        }

        return false;
    }

    /** Storage::disk('public')->putFileAs(...) */
    private function onPublicDisk(Node $node): bool
    {
        return Ast::find($node instanceof Expr\MethodCall ? $node->var : [], fn (Node $n) => Ast::callName($n) === 'disk'
            && $n instanceof Expr\CallLike && Ast::stringValue(Ast::arg($n, 0)) === 'public') !== [];
    }

    private function mentionsPublicPath(?Expr $expr): bool
    {
        return $expr !== null && Ast::find($expr, fn (Node $n) => $n instanceof Expr\FuncCall && Ast::callName($n) === 'public_path') !== [];
    }
}
