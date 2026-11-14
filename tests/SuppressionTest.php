<?php

declare(strict_types=1);

use Plumbline\Plumbline;
use Plumbline\Project\Project;
use Plumbline\Scanner;
use Plumbline\Suppression\Baseline;

const VULNERABLE_CONTROLLER = <<<'PHP'
<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
class A extends Controller {
    public function a(Request $request) {
        %s
        return DB::select("select * from t where c = '{$request->input('c')}'");
    }
}
PHP;

it('honours an inline suppression with a reason', function () {
    $dir = tempApp(['app/Http/Controllers/A.php' => sprintf(VULNERABLE_CONTROLLER, '// plumbline-ignore SQLI-001: c is checked by middleware')]);
    $result = (new Scanner(Plumbline::defaultRules()))->scan(new Project($dir));

    expect($result->findings)->toBe([])->and($result->suppressed)->toBe(1);
});

it('ignores a suppression without a reason', function () {
    $dir = tempApp(['app/Http/Controllers/A.php' => sprintf(VULNERABLE_CONTROLLER, '// plumbline-ignore SQLI-001')]);
    $result = (new Scanner(Plumbline::defaultRules()))->scan(new Project($dir));

    expect($result->findings)->toHaveCount(1);
});

it('ignores a suppression for a different rule', function () {
    $dir = tempApp(['app/Http/Controllers/A.php' => sprintf(VULNERABLE_CONTROLLER, '// plumbline-ignore XSS-001: wrong rule')]);

    expect((new Scanner(Plumbline::defaultRules()))->scan(new Project($dir))->findings)->toHaveCount(1);
});

it('filters baselined findings and survives line shifts', function () {
    $dir = tempApp(['app/Http/Controllers/A.php' => sprintf(VULNERABLE_CONTROLLER, '')]);
    $scanner = new Scanner(Plumbline::defaultRules());
    $first = $scanner->scan(new Project($dir));
    expect($first->findings)->toHaveCount(1);

    $baselinePath = $dir.DIRECTORY_SEPARATOR.'baseline.json';
    Baseline::write($baselinePath, $first->findings);

    // Push the finding down a few lines; the fingerprint must still match.
    file_put_contents($dir.'/app/Http/Controllers/A.php', sprintf(VULNERABLE_CONTROLLER, "\n\n\n"));
    $second = $scanner->scan(new Project($dir), Baseline::load($baselinePath));

    expect($second->findings)->toBe([])->and($second->baselined)->toBe(1);
});
