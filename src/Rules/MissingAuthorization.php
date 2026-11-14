<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use Plumbline\Analysis\Ast;
use Plumbline\Analysis\RouteAction;
use Plumbline\Finding;
use Plumbline\Project\Project;
use Plumbline\Severity;

/**
 * Insecure direct object reference: a signed-in user changes or deletes a model that arrives through
 * route-model binding (/posts/{post}), and nothing checks that the user may touch *that* record.
 *
 * Stays quiet when there is any authorization evidence: can:/role:/permission: middleware, custom
 * route middleware, $this->authorize(), Gate::, ->can(), policies via authorizeResource(), a
 * FormRequest with a real authorize(), ownership comparisons, abort_if/abort_unless, or a model
 * with a global (tenant/team) scope.
 */
final class MissingAuthorization implements ProjectRule
{
    public function meta(): RuleMeta
    {
        return new RuleMeta(
            'AUTHZ-001',
            'missing-authorization',
            'Route changes a URL-chosen record without an authorization check',
            Severity::High,
            'Any signed-in user can change or delete any record by changing the ID in the URL.',
            'CWE-639',
        );
    }

    public function check(Project $project): iterable
    {
        $seen = [];
        foreach ($project->routes()->all() as $route) {
            if (! $route->contextKnown || ! $route->changesState() || ! $route->hasAuthentication()
                || $route->hasAuthorizationMiddleware() || $route->isSigned() || $route->unknownMiddleware() !== []) {
                continue;
            }
            $action = RouteAction::for($route, $project);
            if ($action === null || $action->hasAuthorizationEvidence()) {
                continue;
            }
            foreach ($action->boundModelWrites() as [$variable, $model, $call]) {
                if ($project->models()->hasGlobalScope($model)) {
                    continue;
                }
                $key = $action->file->relativePath.':'.$call->getStartLine();
                if (isset($seen[$key])) {
                    continue; // PUT and PATCH (or several routes) share one action.
                }
                $seen[$key] = true;

                $short = Ast::shortName($model);
                $verb = in_array(Ast::callName($call), ['delete', 'forcedelete', 'detach'], true) ? 'deletes' : 'changes';
                $line = $call->getStartLine();

                yield new Finding(
                    $this->meta()->id,
                    $this->meta()->severity,
                    "{$route->describe()} {$verb} the {$short} chosen in the URL (\${$variable}) without an authorization check, so any signed-in user can do this to any {$short}. Add \$this->authorize('".($verb === 'deletes' ? 'delete' : 'update')."', \${$variable}) or ->can('".($verb === 'deletes' ? 'delete' : 'update').",".lcfirst((string) $short)."') on the route.",
                    $action->file->relativePath,
                    $line,
                    $action->file->line($line),
                );
                break;
            }
        }
    }
}
