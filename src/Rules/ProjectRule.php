<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use Plumbline\Finding;
use Plumbline\Project\Project;

/** A rule that inspects the project as a whole (config, routes, Blade, models). */
interface ProjectRule extends Rule
{
    /** @return iterable<Finding> */
    public function check(Project $project): iterable;
}
