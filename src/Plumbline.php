<?php

declare(strict_types=1);

namespace Plumbline;

use Plumbline\Rules\BladeRawEcho;
use Plumbline\Rules\CommandInjection;
use Plumbline\Rules\CsrfExclusion;
use Plumbline\Rules\DebugModeInProduction;
use Plumbline\Rules\MassAssignment;
use Plumbline\Rules\MissingAuthentication;
use Plumbline\Rules\MissingAuthorization;
use Plumbline\Rules\OpenRedirect;
use Plumbline\Rules\Rule;
use Plumbline\Rules\SqlInjection;
use Plumbline\Rules\UnsafeDeserialization;
use Plumbline\Rules\UnsafeUploadName;
use Plumbline\Rules\WeakCrypto;

final class Plumbline
{
    public const VERSION = '0.1.0';

    public const REPOSITORY = 'https://github.com/Diddyy/Plumbline';

    /** @return list<Rule> */
    public static function defaultRules(): array
    {
        return [
            new SqlInjection(),
            new CommandInjection(),
            new UnsafeDeserialization(),
            new MassAssignment(),
            new MissingAuthorization(),
            new MissingAuthentication(),
            new BladeRawEcho(),
            new OpenRedirect(),
            new UnsafeUploadName(),
            new CsrfExclusion(),
            new DebugModeInProduction(),
            new WeakCrypto(),
        ];
    }
}
