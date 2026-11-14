<?php

declare(strict_types=1);

namespace Plumbline;

enum Severity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';

    public function rank(): int
    {
        return match ($this) {
            self::Critical => 4,
            self::High => 3,
            self::Medium => 2,
            self::Low => 1,
        };
    }

    public function atLeast(self $other): bool
    {
        return $this->rank() >= $other->rank();
    }

    /** SARIF result level. */
    public function sarifLevel(): string
    {
        return match ($this) {
            self::Critical, self::High => 'error',
            self::Medium => 'warning',
            self::Low => 'note',
        };
    }

    /** GitHub code scanning "security-severity" score (0.0-10.0). */
    public function securityScore(): string
    {
        return match ($this) {
            self::Critical => '9.5',
            self::High => '8.0',
            self::Medium => '5.5',
            self::Low => '3.0',
        };
    }
}
