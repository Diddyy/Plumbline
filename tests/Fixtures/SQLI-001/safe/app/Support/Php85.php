<?php

namespace App\Support;

// PHP 8.5 partial function application and first-class callables must not crash the engine.
class Php85
{
    public function run(array $values)
    {
        $trim = trim(...);
        $prefix = str_replace('a', ?, ?);

        return array_map(sprintf('%s-%s', ?, 'x'), $values);
    }
}
