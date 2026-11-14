<?php

declare(strict_types=1);

namespace Plumbline\Analysis;

/**
 * What the engine knows about the value of an expression.
 *
 * - request:   the value is a Request object (calling ->input() on it yields user input)
 * - tainted:   the value contains attacker-controlled data
 * - bag:       the value is the *whole* unfiltered input array ($request->all(), ->except())
 * - validated: the value came out of validated()/safe() (still user data, but key-filtered)
 */
final readonly class Value
{
    private function __construct(
        public bool $request = false,
        public bool $tainted = false,
        public bool $bag = false,
        public bool $validated = false,
        public string $source = '',
    ) {
    }

    public static function clean(): self
    {
        return new self();
    }

    public static function request(): self
    {
        return new self(request: true);
    }

    public static function tainted(string $source, bool $bag = false, bool $validated = false): self
    {
        return new self(tainted: true, bag: $bag, validated: $validated, source: $source);
    }

    public function withoutBag(): self
    {
        return $this->tainted ? self::tainted($this->source, false, $this->validated) : $this;
    }

    /** Union of two values: tainted if either is. Used for concatenation and merges. */
    public static function either(self ...$values): self
    {
        foreach ($values as $value) {
            if ($value->tainted) {
                return self::tainted($value->source);
            }
        }

        return self::clean();
    }
}
