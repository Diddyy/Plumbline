<?php

declare(strict_types=1);

namespace Plumbline;

final readonly class Finding
{
    public function __construct(
        public string $ruleId,
        public Severity $severity,
        public string $message,
        /** Path relative to the scanned project root, forward slashes. */
        public string $file,
        public int $line,
        /** The trimmed source line, used for display and stable fingerprints. */
        public string $snippet = '',
    ) {
    }

    /**
     * A fingerprint that survives unrelated edits elsewhere in the file:
     * it ignores the line number and uses the normalised source line instead.
     */
    public function fingerprint(): string
    {
        $normalised = preg_replace('/\s+/', ' ', trim($this->snippet)) ?? '';

        return substr(hash('sha256', $this->ruleId.'|'.$this->file.'|'.$normalised), 0, 24);
    }

    public function withSeverity(Severity $severity): self
    {
        return new self($this->ruleId, $severity, $this->message, $this->file, $this->line, $this->snippet);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'rule' => $this->ruleId,
            'severity' => $this->severity->value,
            'message' => $this->message,
            'file' => $this->file,
            'line' => $this->line,
            'snippet' => $this->snippet,
            'fingerprint' => $this->fingerprint(),
        ];
    }
}
