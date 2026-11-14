<?php

declare(strict_types=1);

use Plumbline\Plumbline;
use Plumbline\Project\Project;
use Plumbline\Scanner;

it('skips embedded applications that have their own vendor/autoload.php', function () {
    $dir = tempApp([
        'artisan' => '',
        'forum/src/vendor/autoload.php' => '<?php',
        'forum/src/Auth.php' => '<?php function check($password) { return md5($password); }',
        'app/Support/Legacy.php' => '<?php function check($password) { return md5($password); }',
    ]);

    $project = new Project($dir);
    $findings = (new Scanner(Plumbline::defaultRules()))->scan($project)->findings;

    expect($project->skippedEmbeddedApps())->toBe(['forum'])
        ->and(array_map(fn ($f) => $f->file, $findings))->toBe(['app/Support/Legacy.php']);
});

it('skips routes and code that only exist in local environments', function () {
    $dir = tempApp([
        'routes/web.php' => <<<'PHP'
            <?php
            use Illuminate\Support\Facades\Route;
            if (app()->environment('local')) {
                Route::post('/dev/reset/{id}', function ($id) {
                    App\Models\Post::find($id)->delete();
                    return redirect(request('next'));
                });
            }
            PHP,
        'app/Models/Post.php' => '<?php namespace App\Models; class Post extends \Illuminate\Database\Eloquent\Model {}',
    ]);

    $project = new Project($dir);

    expect($project->routes()->all())->toBe([])
        ->and((new Scanner(Plumbline::defaultRules()))->scan($project)->findings)->toBe([]);
});

it('recognises Laravel projects', function () {
    expect((new Project(fixturePath('apps', 'laravel')))->looksLikeLaravel())->toBeTrue()
        ->and((new Project(tempApp(['index.php' => '<?php'])))->looksLikeLaravel())->toBeFalse();
});
