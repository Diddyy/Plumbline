<?php

declare(strict_types=1);

namespace Plumbline\Project;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use Plumbline\Analysis\Ast;

final class ClassInfo
{
    public function __construct(
        public readonly string $name,
        public readonly Stmt\Class_ $node,
        public readonly PhpFile $file,
    ) {
    }

    public function parent(): ?string
    {
        return $this->node->extends !== null ? Ast::nameString($this->node->extends) : null;
    }

    public function shortName(): string
    {
        return (string) Ast::shortName($this->name);
    }

    public function method(string $name): ?Stmt\ClassMethod
    {
        foreach ($this->node->getMethods() as $method) {
            if (strcasecmp($method->name->toString(), $name) === 0) {
                return $method;
            }
        }

        return null;
    }

    /** @return list<string> */
    public function traits(): array
    {
        $out = [];
        foreach ($this->node->getTraitUses() as $use) {
            foreach ($use->traits as $trait) {
                $out[] = Ast::nameString($trait);
            }
        }

        return $out;
    }

    /** Literal value of a property default, e.g. protected $guarded = []. */
    public function propertyDefault(string $name): ?Node\Expr
    {
        foreach ($this->node->getProperties() as $property) {
            foreach ($property->props as $prop) {
                if ($prop->name->toString() === $name) {
                    return $prop->default;
                }
            }
        }

        return null;
    }

    public function hasProperty(string $name): bool
    {
        foreach ($this->node->getProperties() as $property) {
            foreach ($property->props as $prop) {
                if ($prop->name->toString() === $name) {
                    return true;
                }
            }
        }

        return false;
    }

    /** @return list<string> */
    public function attributes(): array
    {
        return Ast::attributeNames($this->node);
    }
}
