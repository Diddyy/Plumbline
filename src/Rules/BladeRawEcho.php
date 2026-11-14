<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use Plumbline\Analysis\Ast;
use Plumbline\Finding;
use Plumbline\Project\Project;
use Plumbline\Severity;

/**
 * {!! $x !!} prints without escaping. We stay quiet for output that is HTML by construction
 * (csrf_field(), $paginator->links(), component $slot/$attributes, literal translations...) and
 * raise the severity when the value visibly comes from the request.
 */
final class BladeRawEcho implements ProjectRule
{
    /** Functions whose output is framework-generated HTML, or already escaped. */
    private const SAFE_FUNCTIONS = [
        'csrf_field', 'method_field', 'e', 'htmlspecialchars', 'htmlentities', 'json_encode_safe', 'vite',
        'route', 'url', 'asset', 'secure_asset', 'mix', 'config', 'view', 'svg', 'clean', 'purify',
        'csp_nonce', 'livewire_scripts', 'livewirescripts', 'livewirestyles', 'strip_tags', 'number_format',
        'count', 'json_encode_attr', 'trans_choice_safe', 'now', 'date',
    ];

    /** Methods that return framework-rendered HTML. */
    private const SAFE_METHODS = [
        'links', 'render', 'tohtml', 'renderbody', 'withqueryString', 'onEachSide', 'toJson',
    ];

    /** Static helpers that produce safe output. */
    private const SAFE_STATIC = [
        'Vite' => true, 'Js' => true, 'Purifier' => true, 'Livewire' => true, 'Html' => true, 'Form' => true, 'Inertia' => true,
    ];

    /** Variables Blade components provide that are escaped/HTML by construction. */
    private const SAFE_VARIABLES = ['slot', 'attributes', '__env', '__laravel_slots', 'errors', 'loop', 'component'];

    private Parser $parser;

    public function __construct()
    {
        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();
    }

    public function meta(): RuleMeta
    {
        return new RuleMeta(
            'XSS-001',
            'blade-raw-echo',
            'Unescaped output in Blade',
            Severity::Medium,
            '{!! !!} prints a value without HTML escaping.',
            'CWE-79',
        );
    }

    public function check(Project $project): iterable
    {
        foreach ($project->bladeFiles() as $blade) {
            foreach ($blade->rawEchoes() as $echo) {
                $verdict = $this->classify($echo['expr']);
                if ($verdict === null) {
                    continue;
                }
                [$severity, $message] = $verdict;
                yield new Finding($this->meta()->id, $severity, $message, $blade->relativePath, $echo['line'], $echo['snippet']);
            }
        }
    }

    /** @return array{0: Severity, 1: string}|null */
    public function classify(string $code): ?array
    {
        try {
            $stmts = $this->parser->parse('<?php '.$code.';');
        } catch (Error) {
            return null; // Not an expression we understand; staying quiet beats guessing.
        }
        $stmt = $stmts[0] ?? null;
        if (! $stmt instanceof Node\Stmt\Expression) {
            return null;
        }
        $expr = $stmt->expr;

        if ($this->readsRequest($expr)) {
            return [Severity::High, "Request data is printed without escaping in {!! {$code} !!}: reflected XSS. Use {{ }} instead."];
        }

        if ($this->isMarkdown($expr)) {
            return [Severity::Medium, "{!! {$code} !!} renders Markdown, which passes raw HTML through by default. Use Str::markdown(\$text, ['html_input' => 'strip', 'allow_unsafe_links' => false]), or sanitise the output."];
        }

        // Calls to helpers (format_amount(), Form::text(), $model->renderBadge()) build HTML on purpose;
        // escaping is their job. We only ask about raw data: $post->body, $item['title'], "{$name}".
        if ($this->isSafe($expr) || ! $this->isRawData($expr)) {
            return null;
        }

        return [Severity::Low, "{!! {$code} !!} prints a value without escaping. If it can contain user-written content, escape it with {{ }} or sanitise it (e.g. with an HTML purifier) first."];
    }

    private function isSafe(Expr $expr): bool
    {
        return match (true) {
            $expr instanceof Node\Scalar\InterpolatedString => array_reduce(
                $expr->parts,
                fn (bool $safe, Node $part) => $safe && ($part instanceof Node\InterpolatedStringPart || ($part instanceof Expr && $this->isSafe($part))),
                true,
            ),
            $expr instanceof Node\Scalar, $expr instanceof Expr\ConstFetch, $expr instanceof Expr\ClassConstFetch => true,
            $expr instanceof Expr\Cast\Int_, $expr instanceof Expr\Cast\Double, $expr instanceof Expr\Cast\Bool_ => true,
            // ['startTag' => '<a href="/x">', 'endTag' => '</a>'] as translation replacements
            $expr instanceof Expr\Array_ => array_reduce($expr->items, fn (bool $safe, $item) => $safe && $this->isSafe($item->value), true),
            $expr instanceof Expr\BinaryOp\Concat => $this->isSafe($expr->left) && $this->isSafe($expr->right),
            $expr instanceof Expr\Ternary => ($expr->if === null || $this->isSafe($expr->if)) && $this->isSafe($expr->else),
            $expr instanceof Expr\BinaryOp\Coalesce => $this->isSafe($expr->left) && $this->isSafe($expr->right),
            $expr instanceof Expr\BinaryOp => true, // arithmetic and comparisons; Concat is handled above
            $expr instanceof Expr\Variable => is_string($expr->name) && in_array($expr->name, self::SAFE_VARIABLES, true),
            ($expr instanceof Expr\StaticCall || $expr instanceof Expr\MethodCall)
                && in_array(Ast::callName($expr), ['markdown', 'inlinemarkdown'], true)
                => $this->stripsHtml(Ast::arg($expr, $expr instanceof Expr\StaticCall ? 1 : 0, 'options')),
            $expr instanceof Expr\FuncCall => $this->isSafeFunction($expr),
            $expr instanceof Expr\MethodCall, $expr instanceof Expr\NullsafeMethodCall => in_array(Ast::callName($expr), array_map('strtolower', self::SAFE_METHODS), true)
                || $this->isSafeVariableChain($expr),
            $expr instanceof Expr\StaticCall => isset(self::SAFE_STATIC[(string) Ast::shortName(Ast::className($expr))]),
            $expr instanceof Expr\PropertyFetch => $this->isSafeVariableChain($expr),
            default => false,
        };
    }

    /** Functions that pass their argument through without escaping it. */
    private const PASSTHROUGH = [
        'nl2br', 'trim', 'ucfirst', 'ucwords', 'strtoupper', 'strtolower', 'str_replace', 'sprintf', 'implode',
        'html_entity_decode', 'htmlspecialchars_decode', 'wordwrap', 'urldecode', 'stripslashes', 'str_limit',
        'mb_strtoupper', 'mb_strtolower', 'mb_substr', 'substr', 'join', 'strval',
    ];

    /** Does the expression print stored or passed-in data (rather than the output of an HTML helper)? */
    private function isRawData(Expr $expr): bool
    {
        return match (true) {
            $expr instanceof Expr\Variable => ! $this->isSafe($expr),
            $expr instanceof Expr\PropertyFetch, $expr instanceof Expr\NullsafePropertyFetch,
            $expr instanceof Expr\StaticPropertyFetch, $expr instanceof Expr\ArrayDimFetch => ! $this->isSafeVariableChain($expr),
            $expr instanceof Expr\BinaryOp\Concat, $expr instanceof Expr\BinaryOp\Coalesce => $this->isRawData($expr->left) || $this->isRawData($expr->right),
            $expr instanceof Expr\Ternary => ($expr->if !== null && $this->isRawData($expr->if)) || $this->isRawData($expr->else),
            $expr instanceof Node\Scalar\InterpolatedString => array_filter($expr->parts, fn ($p) => $p instanceof Expr && $this->isRawData($p)) !== [],
            $expr instanceof Expr\FuncCall => $this->rawThroughFunction($expr),
            $expr instanceof Expr\StaticCall => Ast::shortName(Ast::className($expr)) === 'Str'
                && array_filter(Ast::args($expr), fn (Node\Arg $a) => $this->isRawData($a->value)) !== [],
            default => false,
        };
    }

    private function rawThroughFunction(Expr\FuncCall $call): bool
    {
        $name = Ast::callName($call);
        // __('Hi :name', ['name' => $user->name]): replacements are inserted unescaped.
        if (in_array($name, ['__', 'trans', 'trans_choice', 'lang'], true)) {
            return ! $this->isSafeFunction($call);
        }
        if (in_array($name, self::PASSTHROUGH, true)) {
            return array_filter(Ast::args($call), fn (Node\Arg $a) => $this->isRawData($a->value)) !== [];
        }

        return false;
    }

    private function isSafeFunction(Expr\FuncCall $call): bool
    {
        $name = Ast::callName($call);
        if ($name === null) {
            return false;
        }
        if (in_array($name, self::SAFE_FUNCTIONS, true)) {
            return true;
        }
        // __('auth.failed') is safe; __('welcome', ['name' => $user->name]) interpolates unescaped values.
        if (in_array($name, ['__', 'trans', 'trans_choice', 'lang'], true)) {
            $replacements = Ast::arg($call, $name === 'trans_choice' ? 2 : 1, 'replace');

            return Ast::stringValue(Ast::arg($call, 0)) !== null && ($replacements === null || $this->isSafe($replacements));
        }
        // nl2br(e($text)) is the classic safe pattern; nl2br($text) is not.
        if ($name === 'nl2br') {
            $inner = Ast::arg($call, 0);

            return $inner !== null && $this->isSafe($inner);
        }

        return false;
    }

    /** $slot->toHtml(), $attributes->merge([...]) */
    private function isSafeVariableChain(Expr $expr): bool
    {
        $root = $expr;
        while ($root instanceof Expr\MethodCall || $root instanceof Expr\PropertyFetch || $root instanceof Expr\NullsafeMethodCall) {
            $root = $root->var;
        }

        return $root instanceof Expr\Variable && is_string($root->name) && in_array($root->name, self::SAFE_VARIABLES, true)
            && $root->name !== 'errors';
    }

    private function readsRequest(Expr $expr): bool
    {
        $inputMethods = ['input', 'get', 'query', 'post', 'all', 'string', 'str', 'header', 'cookie', 'fullurl', 'url', 'path', 'segment', 'json', 'old'];

        return Ast::find($expr, function (Node $n) use ($inputMethods): bool {
            // request('q') and old('email') read input; request()->user() does not.
            if ($n instanceof Expr\FuncCall) {
                return Ast::callName($n) === 'old' || (Ast::callName($n) === 'request' && Ast::args($n) !== []);
            }
            if ($n instanceof Expr\MethodCall && in_array(Ast::callName($n), $inputMethods, true)) {
                return $n->var instanceof Expr\FuncCall && Ast::callName($n->var) === 'request' && Ast::args($n->var) === [];
            }
            if ($n instanceof Expr\StaticCall) {
                return (Ast::isFacade($n, 'Request') || Ast::isFacade($n, 'Input')) && in_array(Ast::callName($n), $inputMethods, true);
            }
            if ($n instanceof Expr\Variable) {
                return in_array($n->name, ['_GET', '_POST', '_REQUEST', '_COOKIE'], true);
            }

            return false;
        }) !== [];
    }

    private function isMarkdown(Expr $expr): bool
    {
        $calls = Ast::find($expr, fn (Node $n) => in_array(Ast::callName($n), ['markdown', 'inlinemarkdown'], true));
        foreach ($calls as $call) {
            /** @var Expr\CallLike $call */
            $options = Ast::arg($call, $call instanceof Expr\StaticCall ? 1 : 0, 'options');
            if (! $this->stripsHtml($options)) {
                return true;
            }
        }

        return false;
    }

    private function stripsHtml(?Expr $options): bool
    {
        if (! $options instanceof Expr\Array_) {
            return false;
        }
        foreach ($options->items as $item) {
            if ($item !== null && Ast::stringValue($item->key) === 'html_input' && in_array(Ast::stringValue($item->value), ['strip', 'escape'], true)) {
                return true;
            }
        }

        return false;
    }
}
