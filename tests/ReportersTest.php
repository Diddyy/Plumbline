<?php

declare(strict_types=1);

use JsonSchema\Validator;
use Plumbline\Plumbline;
use Plumbline\Project\Project;
use Plumbline\Report\GithubReporter;
use Plumbline\Report\JsonReporter;
use Plumbline\Report\SarifReporter;
use Plumbline\Scanner;

function scanResultFor(string $ruleId)
{
    return (new Scanner(Plumbline::defaultRules()))->scan(new Project(fixturePath($ruleId, 'vulnerable'), ['vendor']));
}

it('produces SARIF 2.1.0 that validates against the official schema', function () {
    $result = scanResultFor('SQLI-001');
    expect($result->findings)->not->toBeEmpty();

    $sarif = json_decode((new SarifReporter())->render($result, Plumbline::defaultRules()));
    $schema = json_decode((string) file_get_contents(__DIR__.'/schema/sarif-2.1.0.json'));

    $validator = new Validator();
    $validator->validate($sarif, $schema);

    expect($validator->getErrors())->toBe([]);
    expect($sarif->runs[0]->results[0]->ruleId)->toBe('SQLI-001')
        ->and($sarif->runs[0]->tool->driver->rules)->toHaveCount(count(Plumbline::defaultRules()));
});

it('produces JSON with a summary and stable fingerprints', function () {
    $json = json_decode((new JsonReporter())->render(scanResultFor('MASS-001'), []), true);

    expect($json['summary']['findings'])->toBe(count($json['findings']))
        ->and($json['findings'][0])->toHaveKeys(['rule', 'severity', 'message', 'file', 'line', 'fingerprint']);
});

it('escapes GitHub workflow command properties', function () {
    $output = (new GithubReporter())->render(scanResultFor('CMD-001'), []);

    expect($output)->toStartWith('::error file=app/Http/Controllers/ToolsController.php,line=')
        ->and($output)->toContain('title=Plumbline CMD-001::');
});
