<?php

declare(strict_types=1);

namespace Plumbline\Analysis;

/**
 * Variable state inside one function body, updated in source order.
 *
 * Assignments made inside a branch or loop never *clear* taint (the other path may still be
 * tainted); only unconditional assignments at the top level of the body do.
 */
final class Scope
{
    /** @var array<string, Value> */
    private array $vars = [];

    /** @var array<string, bool> input key => true when its validation rules make it injection-safe */
    private array $validation = [];

    /** @var array<string, string> variable => class name, when known (typed params, Model::find(), new X) */
    private array $types = [];

    /** @var list<\PhpParser\Node\Expr> conditions of the if/elseif branches we are inside */
    private array $guards = [];

    /** @var array<string, true> variables proven to start with a same-origin prefix ('/...') */
    private array $prefixChecked = [];

    public function pushGuard(\PhpParser\Node\Expr $condition): void
    {
        $this->guards[] = $condition;
    }

    public function popGuard(): void
    {
        array_pop($this->guards);
    }

    /** @return list<\PhpParser\Node\Expr> */
    public function guards(): array
    {
        return $this->guards;
    }

    public function markPrefixChecked(string $name): void
    {
        $this->prefixChecked[$name] = true;
    }

    public function isPrefixChecked(string $name): bool
    {
        return isset($this->prefixChecked[$name]);
    }

    public function setType(string $name, ?string $class): void
    {
        if ($class === null) {
            unset($this->types[$name]);
        } else {
            $this->types[$name] = $class;
        }
    }

    public function type(string $name): ?string
    {
        return $this->types[$name] ?? null;
    }

    public function get(string $name): ?Value
    {
        return $this->vars[$name] ?? null;
    }

    public function set(string $name, Value $value, bool $conditional): void
    {
        $previous = $this->vars[$name] ?? null;
        if ($conditional && $previous !== null && ($previous->tainted || $previous->request) && ! $value->tainted && ! $value->request) {
            return;
        }
        $this->vars[$name] = $value;
    }

    /** Mark a variable as sanitised (e.g. after an in_array() allowlist guard). */
    public function sanitise(string $name): void
    {
        if (isset($this->vars[$name]) && $this->vars[$name]->tainted) {
            $this->vars[$name] = Value::clean();
        }
    }

    /** @param array<string, bool> $rules */
    public function addValidation(array $rules): void
    {
        foreach ($rules as $key => $safe) {
            $this->validation[$key] = ($this->validation[$key] ?? false) || $safe;
        }
    }

    public function isValidatedSafe(?string $key): bool
    {
        return $key !== null && ($this->validation[$key] ?? false);
    }
}
