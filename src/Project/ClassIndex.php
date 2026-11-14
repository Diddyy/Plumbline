<?php

declare(strict_types=1);

namespace Plumbline\Project;

use PhpParser\Node\Stmt;
use Plumbline\Analysis\Ast;

/** Every class declared in the scanned project, by fully-qualified name. */
final class ClassIndex
{
    /** @var array<string, ClassInfo> lower-cased FQCN => info */
    private array $classes = [];

    /** @param list<PhpFile> $files */
    public function __construct(array $files)
    {
        foreach ($files as $file) {
            foreach (Ast::find($file->stmts(), fn ($n) => $n instanceof Stmt\Class_ && $n->name !== null) as $class) {
                /** @var Stmt\Class_ $class */
                $name = $class->namespacedName?->toString() ?? $class->name?->toString() ?? '';
                $this->classes[strtolower($name)] = new ClassInfo($name, $class, $file);
            }
        }
    }

    public function get(?string $name): ?ClassInfo
    {
        return $name === null ? null : ($this->classes[strtolower(ltrim($name, '\\'))] ?? null);
    }

    /** @return list<ClassInfo> */
    public function all(): array
    {
        return array_values($this->classes);
    }

    /**
     * The class and its ancestors' names, following parents declared in the project and stopping at
     * the first parent declared elsewhere (vendor), which is included by name only.
     *
     * @return list<string>
     */
    public function lineage(string $name): array
    {
        $out = [];
        $current = $name;
        $guard = 0;
        while ($current !== null && $guard++ < 32) {
            $out[] = $current;
            $current = $this->get($current)?->parent();
        }

        return $out;
    }

    /** True when the class or an ancestor matches one of the given FQCNs or short names. */
    public function extends(string $name, string ...$targets): bool
    {
        foreach ($this->lineage($name) as $ancestor) {
            foreach ($targets as $target) {
                if (strcasecmp($ancestor, $target) === 0
                    || (! str_contains($target, '\\') && strcasecmp((string) Ast::shortName($ancestor), $target) === 0)) {
                    return true;
                }
            }
        }

        return false;
    }

    public function isModel(string $name): bool
    {
        return $this->extends(
            $name,
            'Illuminate\\Database\\Eloquent\\Model',
            'Illuminate\\Foundation\\Auth\\User',
            'Illuminate\\Database\\Eloquent\\Relations\\Pivot',
            'Jenssegers\\Mongodb\\Eloquent\\Model',
            'MongoDB\\Laravel\\Eloquent\\Model',
        );
    }

    public function isController(string $name): bool
    {
        return str_ends_with($name, 'Controller')
            || $this->extends($name, 'Illuminate\\Routing\\Controller', 'App\\Http\\Controllers\\Controller');
    }

    public function isLivewire(string $name): bool
    {
        return $this->extends($name, 'Livewire\\Component', 'Livewire\\Form');
    }

    public function isFormRequest(string $name): bool
    {
        return $this->extends($name, 'Illuminate\\Foundation\\Http\\FormRequest');
    }
}
