<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use PhpParser\Node;
use Plumbline\Analysis\FunctionContext;
use Plumbline\Analysis\Scope;
use Plumbline\Finding;

/**
 * A rule that looks for user input reaching a dangerous sink.
 *
 * The taint engine walks every function body once, in source order, and offers
 * each node to every taint rule together with the taint state at that point.
 */
interface TaintRule extends Rule
{
    /** @return iterable<Finding> */
    public function inspect(Node $node, Scope $scope, FunctionContext $context): iterable;
}
