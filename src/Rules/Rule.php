<?php

declare(strict_types=1);

namespace Plumbline\Rules;

interface Rule
{
    public function meta(): RuleMeta;
}
