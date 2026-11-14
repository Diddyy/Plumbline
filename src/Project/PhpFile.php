<?php

declare(strict_types=1);

namespace Plumbline\Project;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\Parser;

final class PhpFile
{
    /** @var list<Node\Stmt>|null */
    private ?array $stmts = null;

    private bool $parsed = false;

    private ?string $parseError = null;

    /** @var list<string>|null */
    private ?array $lines = null;

    public function __construct(
        public readonly string $path,
        /** Relative to the project root, forward slashes. */
        public readonly string $relativePath,
        public readonly string $code,
        private readonly Parser $parser,
    ) {
    }

    /**
     * Statements with names resolved (namespacedName on classes, resolvedName attribute on names).
     *
     * @return list<Node\Stmt>
     */
    public function stmts(): array
    {
        if (! $this->parsed) {
            $this->parsed = true;
            try {
                $stmts = $this->parser->parse($this->code) ?? [];
                $traverser = new NodeTraverser(new NameResolver(null, ['replaceNodes' => false]));
                /** @var list<Node\Stmt> $stmts */
                $stmts = $traverser->traverse($stmts);
                $this->stmts = $stmts;
            } catch (Error $e) {
                $this->parseError = $e->getMessage();
                $this->stmts = [];
            }
        }

        return $this->stmts ?? [];
    }

    public function parseError(): ?string
    {
        $this->stmts();

        return $this->parseError;
    }

    public function line(int $number): string
    {
        $this->lines ??= preg_split('/\R/', $this->code) ?: [];

        return trim($this->lines[$number - 1] ?? '');
    }
}
