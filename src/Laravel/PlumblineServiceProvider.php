<?php

declare(strict_types=1);

namespace Plumbline\Laravel;

use Illuminate\Console\Application as Artisan;
use Illuminate\Support\ServiceProvider;
use Plumbline\Console\RulesCommand;
use Plumbline\Console\ScanCommand;

/**
 * Registers `php artisan plumbline:scan` and `php artisan plumbline:rules` through package
 * auto-discovery. The commands are the same as vendor/bin/plumbline; nothing is booted or executed
 * from the scanned code.
 */
final class PlumblineServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        Artisan::starting(function (Artisan $artisan): void {
            $scan = new ScanCommand();
            $scan->setName('plumbline:scan');
            $scan->getDefinition()->getArgument('path')->setDefault($this->app->basePath());

            $rules = new RulesCommand();
            $rules->setName('plumbline:rules');

            $artisan->addCommands([$scan, $rules]);
        });
    }
}
