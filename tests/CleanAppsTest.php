<?php

declare(strict_types=1);

dataset('clean apps', [
    'laravel/laravel' => ['laravel'],
    'laravel/react-starter-kit' => ['react-starter-kit'],
]);

it('reports nothing on official Laravel skeletons', function (string $app) {
    $findings = scanFixture(fixturePath('apps', $app));

    expect(array_map(fn ($f) => "{$f->ruleId} {$f->file}:{$f->line}", $findings))->toBe([]);
})->with('clean apps');

it('still parses the starter kit routes it stays silent about', function () {
    $project = new Plumbline\Project\Project(fixturePath('apps', 'react-starter-kit'));
    $routes = array_map(fn ($r) => $r->describe(), $project->routes()->all());

    // Guards against "silent because nothing was parsed".
    expect(count($routes))->toBeGreaterThan(15)
        ->and(implode("\n", $routes))->toContain('PATCH /settings/profile', 'POST /login');
});
