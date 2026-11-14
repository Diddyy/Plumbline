<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use Plumbline\Finding;
use Plumbline\Project\Project;
use Plumbline\Severity;

/**
 * CSRF protection switched off for routes that look like ordinary browser routes.
 * Exclusions for webhooks and payment callbacks (which can't send a token) are expected and ignored.
 */
final class CsrfExclusion implements ProjectRule
{
    private const MACHINE_TO_MACHINE = '/(web)?hooks?|callback|notif|ipn|stripe|paypal|mollie|paddle|braintree|square|razorpay|twilio|mailgun|postmark|sendgrid|\bses\b|\bsns\b|slack|discord|telegram|github|gitlab|bitbucket|shopify|cashier|lemon|coinbase|^\/?api(\/|$)|broadcasting|pusher|zapier|\bsms\b|payment|\bpay\b|saml|acs|sso|oauth|mpesa|flutterwave|paystack|(^|\/)(card|cal)?dav(\/|$)|\.well-known/i';

    public function meta(): RuleMeta
    {
        return new RuleMeta(
            'CSRF-001',
            'csrf-exclusion',
            'CSRF protection disabled for browser routes',
            Severity::Medium,
            'Routes excluded from CSRF verification can be triggered by any website the user visits.',
            'CWE-352',
        );
    }

    public function check(Project $project): iterable
    {
        $routes = $project->routes();

        foreach ($routes->csrfExclusions() as ['pattern' => $pattern, 'file' => $file, 'line' => $line]) {
            $snippet = $project->file($file)?->line($line) ?? $pattern;
            $trimmed = trim($pattern, '/');
            if ($trimmed === '*' || $trimmed === '') {
                yield new Finding($this->meta()->id, Severity::High, "CSRF protection is disabled for every route ('{$pattern}'). Exclude only the specific webhook paths that need it.", $file, $line, $snippet);
            } elseif (! preg_match(self::MACHINE_TO_MACHINE, $pattern)) {
                $wildcard = str_contains($pattern, '*');
                yield new Finding(
                    $this->meta()->id,
                    $wildcard ? Severity::Medium : Severity::Low,
                    "'{$pattern}' is excluded from CSRF verification but doesn't look like a webhook. If browsers submit to it, any website can submit on the user's behalf.",
                    $file,
                    $line,
                    $snippet,
                );
            }
        }

        foreach ($routes->all() as $route) {
            if (in_array('csrf', $route->withoutMiddleware, true) && $route->changesState()
                && ! preg_match(self::MACHINE_TO_MACHINE, $route->uri)) {
                $snippet = $project->file($route->file)?->line($route->line) ?? '';
                yield new Finding($this->meta()->id, Severity::Medium, "{$route->describe()} removes CSRF verification with withoutMiddleware(). If browsers submit to it, any website can submit on the user's behalf.", $route->file, $route->line, $snippet);
            }
        }
    }
}
