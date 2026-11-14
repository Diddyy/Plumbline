<?php

declare(strict_types=1);

use Plumbline\Plumbline;

/*
 * The precision contract.
 *
 * tests/Fixtures/<RULE-ID>/vulnerable  every line marked "expect: <RULE-ID>" must be reported,
 *                                      and nothing else may be.
 * tests/Fixtures/<RULE-ID>/safe        must produce zero findings for that rule.
 */

$ruleIds = array_map(fn ($rule) => $rule->meta()->id, Plumbline::defaultRules());

dataset('rules', array_combine($ruleIds, array_map(fn ($id) => [$id], $ruleIds)));

it('reports exactly the marked lines in the vulnerable fixture', function (string $ruleId) {
    $dir = fixturePath($ruleId, 'vulnerable');
    expect(is_dir($dir))->toBeTrue("Missing fixture directory {$dir}");

    $expected = expectedMarkers($dir, $ruleId);
    expect($expected)->not->toBeEmpty("{$ruleId} vulnerable fixture has no expect: markers");

    expect(findingKeys(scanFixture($dir, $ruleId)))->toBe($expected);
})->with('rules');

it('stays silent on the safe fixture', function (string $ruleId) {
    $dir = fixturePath($ruleId, 'safe');
    expect(is_dir($dir))->toBeTrue("Missing fixture directory {$dir}");

    $findings = scanFixture($dir, $ruleId);

    expect(array_map(fn ($f) => "{$f->file}:{$f->line} {$f->message}", $findings))->toBe([]);
})->with('rules');
