<?php

declare(strict_types=1);

namespace Plumbline\Report;

use Plumbline\Plumbline;
use Plumbline\ScanResult;

/** SARIF 2.1.0, ready for GitHub code scanning (github/codeql-action/upload-sarif). */
final class SarifReporter implements Reporter
{
    public function render(ScanResult $result, array $rules): string
    {
        $ruleIndex = [];
        $descriptors = [];
        foreach ($rules as $i => $rule) {
            $meta = $rule->meta();
            $ruleIndex[$meta->id] = $i;
            $descriptors[] = [
                'id' => $meta->id,
                'name' => $meta->name,
                'shortDescription' => ['text' => $meta->title],
                'fullDescription' => ['text' => $meta->summary],
                'helpUri' => $meta->helpUri(),
                'help' => ['text' => $meta->summary.' See '.$meta->helpUri(), 'markdown' => $meta->summary.' [Read more]('.$meta->helpUri().')'],
                'defaultConfiguration' => ['level' => $meta->severity->sarifLevel()],
                'properties' => [
                    'tags' => ['security', 'laravel', 'external/cwe/'.strtolower($meta->cwe)],
                    'precision' => 'high',
                    'security-severity' => $meta->severity->securityScore(),
                ],
            ];
        }

        $results = [];
        foreach ($result->findings as $finding) {
            $entry = [
                'ruleId' => $finding->ruleId,
                'level' => $finding->severity->sarifLevel(),
                'message' => ['text' => $finding->message],
                'locations' => [[
                    'physicalLocation' => [
                        'artifactLocation' => ['uri' => $finding->file, 'uriBaseId' => '%SRCROOT%'],
                        'region' => ['startLine' => max(1, $finding->line)],
                    ],
                ]],
                'partialFingerprints' => ['plumbline/v1' => $finding->fingerprint()],
                'properties' => ['severity' => $finding->severity->value, 'security-severity' => $finding->severity->securityScore()],
            ];
            if (isset($ruleIndex[$finding->ruleId])) {
                $entry['ruleIndex'] = $ruleIndex[$finding->ruleId];
            }
            $results[] = $entry;
        }

        return json_encode([
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [[
                'tool' => [
                    'driver' => [
                        'name' => 'Plumbline',
                        'semanticVersion' => Plumbline::VERSION,
                        'informationUri' => Plumbline::REPOSITORY,
                        'rules' => $descriptors,
                    ],
                ],
                'results' => $results,
            ]],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n";
    }
}
