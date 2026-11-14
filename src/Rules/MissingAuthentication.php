<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use Plumbline\Analysis\Ast;
use Plumbline\Analysis\RouteAction;
use Plumbline\Finding;
use Plumbline\Project\Project;
use Plumbline\Severity;

/**
 * A route anyone can call (no auth middleware) that changes or deletes *existing* records.
 *
 * Public routes that only create things (contact forms, sign-ups, comments) are fine and are not
 * reported. Neither are routes behind custom middleware we don't recognise, signed URLs, guest-only
 * routes, well-known webhook/auth paths, or actions that check the user themselves.
 */
final class MissingAuthentication implements ProjectRule
{
    private const EXEMPT_URI = '/(^|\/)(login|logout|register|password|forgot|reset|verify|verification|two-factor|2fa|webhooks?|hooks?|stripe|paypal|mollie|paddle|callback|ipn|notify|broadcasting|sanctum|livewire|telescope|horizon|nova|pulse|_ignition|oauth|saml|sso|unsubscribe|invitations?\/accept)(\/|$|-)|\{[^}]*(token|code|hash|secret|signature|key|uuid|ulid)[^}]*\}/i';

    public function meta(): RuleMeta
    {
        return new RuleMeta(
            'AUTH-001',
            'missing-authentication',
            'Unauthenticated route changes existing records',
            Severity::High,
            'A route with no authentication middleware updates or deletes existing records.',
            'CWE-306',
        );
    }

    public function check(Project $project): iterable
    {
        foreach ($project->routes()->all() as $route) {
            if (! $route->contextKnown || ! $route->changesState() || $route->hasAuthentication() || $route->isGuestOnly()
                || $route->unknownMiddleware() !== [] || preg_match(self::EXEMPT_URI, $route->uri)) {
                continue;
            }
            // PublicDisputeController, PublicFormController: deliberately open to everyone.
            // ...and webhook receivers (TelegramWebhookController), which authenticate by signature or secret.
            $controller = (string) Ast::shortName($route->controller);
            if ($route->controller !== null && (str_starts_with($controller, 'Public') || stripos($controller, 'webhook') !== false)) {
                continue;
            }
            $action = RouteAction::for($route, $project);
            if ($action === null || $action->referencesCurrentUser()) {
                continue;
            }
            $writes = $action->existingRecordWrites();
            if ($writes === []) {
                continue;
            }
            [$model, $call] = $writes[0];
            $file = $project->file($action->file->relativePath);
            $line = $call->getStartLine();

            yield new Finding(
                $this->meta()->id,
                $this->meta()->severity,
                "{$route->describe()} has no authentication middleware, but {$action->name()} changes existing {$model} records. Anyone can call it. Add ->middleware('auth') (or a signed URL if it is meant to be public).",
                $action->file->relativePath,
                $line,
                $file?->line($line) ?? '',
            );
        }
    }
}
