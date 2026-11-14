<?php

declare(strict_types=1);

namespace Plumbline\Project;

final class BladeFile
{
    public function __construct(
        public readonly string $path,
        public readonly string $relativePath,
        public readonly string $code,
    ) {
    }

    /**
     * Every raw echo ({!! expr !!}) outside comments and @verbatim blocks.
     *
     * @return list<array{expr: string, line: int, snippet: string}>
     */
    public function rawEchoes(): array
    {
        // Blank out comments and verbatim blocks but keep newlines so line numbers stay true.
        $code = preg_replace_callback(
            '/\{\{--.*?--\}\}|@verbatim.*?@endverbatim/s',
            fn (array $m) => preg_replace('/[^\n]/', ' ', $m[0]) ?? '',
            $this->code,
        ) ?? $this->code;

        preg_match_all('/\{!!(.*?)!!\}/s', $code, $matches, PREG_OFFSET_CAPTURE);

        $lines = preg_split('/\R/', $this->code) ?: [];
        $out = [];
        foreach ($matches[1] as [$expr, $offset]) {
            $line = substr_count($code, "\n", 0, $offset) + 1;
            $out[] = [
                'expr' => trim($expr),
                'line' => $line,
                'snippet' => trim($lines[$line - 1] ?? ''),
            ];
        }

        return $out;
    }

    public function line(int $number): string
    {
        $lines = preg_split('/\R/', $this->code) ?: [];

        return trim($lines[$number - 1] ?? '');
    }
}
