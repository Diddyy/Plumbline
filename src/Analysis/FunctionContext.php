<?php

declare(strict_types=1);

namespace Plumbline\Analysis;

use PhpParser\Node;
use Plumbline\Finding;
use Plumbline\Project\ClassInfo;
use Plumbline\Project\PhpFile;
use Plumbline\Project\Project;
use Plumbline\Rules\RuleMeta;

/** Where the engine currently is: which file, class and function, and what kind of code it is. */
final class FunctionContext
{
    public readonly bool $isController;

    public readonly bool $isLivewire;

    public readonly bool $isFormRequest;

    public readonly bool $isRouteFile;

    /** @var array<string, bool> Livewire public property => user-controllable */
    private array $livewireProps = [];

    public function __construct(
        public readonly Project $project,
        public readonly PhpFile $file,
        public readonly ?ClassInfo $class,
        public readonly ?Node\FunctionLike $function,
    ) {
        $classes = $project->classes();
        $name = $class?->name;
        $this->isController = $name !== null && $classes->isController($name);
        $this->isLivewire = $name !== null && $classes->isLivewire($name);
        $this->isFormRequest = $name !== null && $classes->isFormRequest($name);
        $this->isRouteFile = str_starts_with($file->relativePath, 'routes/');

        if ($this->isLivewire && $class !== null) {
            $this->indexLivewireProperties($class);
        }
    }

    public function isUserControlledProperty(string $name): bool
    {
        return $this->livewireProps[$name] ?? false;
    }

    /** True when parameters of this function arrive straight from the client (route params, Livewire actions). */
    public function paramsAreUserInput(Node\FunctionLike $function): bool
    {
        if ($function instanceof Node\Stmt\ClassMethod) {
            if (! $function->isPublic() || $function->isStatic()) {
                return false;
            }
            $method = strtolower($function->name->toString());
            if (str_starts_with($method, '__') && $method !== '__invoke') {
                return false;
            }
            if ($this->isLivewire) {
                // render(), boot(), hydrate() etc. are not called with client data.
                return ! in_array($method, ['render', 'boot', 'booted', 'hydrate', 'dehydrate', 'rules', 'messages', 'validationattributes'], true)
                    && ! str_starts_with($method, 'get');
            }

            return $this->isController;
        }

        // Closures registered directly in route files: Route::get('/{id}', function ($id) { ... }).
        return $this->isRouteFile && ($function instanceof Node\Expr\Closure || $function instanceof Node\Expr\ArrowFunction);
    }

    public function finding(RuleMeta $meta, Node $node, string $message): Finding
    {
        $line = $node->getStartLine();

        return new Finding($meta->id, $meta->severity, $message, $this->file->relativePath, $line, $this->file->line($line));
    }

    private function indexLivewireProperties(ClassInfo $class): void
    {
        $classes = $this->project->classes();
        foreach ($class->node->getProperties() as $property) {
            if (! $property->isPublic() || $property->isStatic()) {
                continue;
            }
            $locked = false;
            foreach (Ast::attributeNames($property) as $attribute) {
                if (Ast::shortName($attribute) === 'Locked') {
                    $locked = true;
                }
            }
            $types = Ast::typeNames($property->type);
            $controllable = ! $locked;
            foreach ($types as $type) {
                // int/float/bool can't carry an injection payload; Eloquent models are locked by Livewire.
                if (in_array($type, ['int', 'float', 'bool', 'false', 'true'], true)
                    || ($classes->get($type) !== null && $classes->isModel($type))
                    || in_array(Ast::shortName($type), ['Model', 'Collection', 'Carbon', 'CarbonImmutable', 'DateTime', 'DateTimeImmutable'], true)) {
                    $controllable = false;
                }
            }
            foreach ($property->props as $prop) {
                $this->livewireProps[$prop->name->toString()] = $controllable;
            }
        }
    }
}
