<?php

declare(strict_types=1);

namespace Plumbline\Project;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Plumbline\Analysis\Ast;

/** Eloquent models and what protects them from mass assignment. */
final class ModelIndex
{
    /** Attribute names that should never be mass assignable from raw request input. */
    public const SENSITIVE_ATTRIBUTES = [
        'is_admin', 'admin', 'is_super_admin', 'superadmin', 'role', 'roles', 'role_id', 'permissions',
        'user_id', 'owner_id', 'team_id', 'tenant_id', 'account_id', 'organization_id', 'company_id',
        'balance', 'credits', 'credit', 'coins', 'points', 'wallet', 'is_verified', 'verified',
        'email_verified_at', 'approved', 'is_approved', 'is_banned', 'banned', 'is_staff', 'staff',
        'rank', 'level', 'vip', 'is_vip', 'plan', 'subscription', 'price', 'amount', 'paid', 'is_paid',
    ];

    private bool $globallyUnguarded = false;

    private ?string $unguardLocation = null;

    public function __construct(private readonly Project $project)
    {
        foreach ($project->phpFiles() as $file) {
            foreach (Ast::find($file->stmts(), fn (Node $n) => $n instanceof Expr\StaticCall && Ast::callName($n) === 'unguard') as $call) {
                /** @var Expr\StaticCall $call */
                $class = Ast::className($call);
                if ($class !== null && ($project->classes()->isModel($class) || Ast::shortName($class) === 'Model')) {
                    $this->globallyUnguarded = true;
                    $this->unguardLocation = $file->relativePath.':'.$call->getStartLine();
                }
            }
        }
    }

    public function globallyUnguarded(): bool
    {
        return $this->globallyUnguarded;
    }

    public function unguardLocation(): ?string
    {
        return $this->unguardLocation;
    }

    public function isModel(?string $class): bool
    {
        return $class !== null && $this->project->classes()->get($class) !== null && $this->project->classes()->isModel($class);
    }

    /**
     * True when $guarded is explicitly empty ([] or false) on the model or a project ancestor.
     */
    public function isUnguarded(string $class): bool
    {
        foreach ($this->project->classes()->lineage($class) as $name) {
            $info = $this->project->classes()->get($name);
            if ($info === null) {
                break;
            }
            if ($info->hasProperty('guarded')) {
                $default = $info->propertyDefault('guarded');

                return ($default instanceof Expr\Array_ && $default->items === [])
                    || ($default instanceof Expr\ConstFetch && strtolower($default->name->toString()) === 'false');
            }
            if (in_array('Illuminate\\Database\\Eloquent\\Attributes\\Unguarded', $info->attributes(), true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Fillable attributes declared on the model, or null when it doesn't declare any.
     *
     * @return list<string>|null
     */
    public function fillable(string $class): ?array
    {
        foreach ($this->project->classes()->lineage($class) as $name) {
            $info = $this->project->classes()->get($name);
            if ($info === null) {
                break;
            }
            if ($info->hasProperty('fillable')) {
                return Ast::stringList($info->propertyDefault('fillable'));
            }
            foreach ($info->node->attrGroups as $group) {
                foreach ($group->attrs as $attr) {
                    if (Ast::shortName(Ast::nameString($attr->name)) === 'Fillable' && isset($attr->args[0])) {
                        return Ast::stringList($attr->args[0]->value);
                    }
                }
            }
        }

        return null;
    }

    /** @return list<string> */
    public function sensitiveFillable(string $class): array
    {
        return array_values(array_intersect(
            array_map('strtolower', $this->fillable($class) ?? []),
            self::SENSITIVE_ATTRIBUTES,
        ));
    }

    /**
     * True when route-model binding on this model is probably already scoped to the current tenant/team
     * (a global scope, #[ScopedBy], or a tenancy trait). Authorization rules stay quiet for these.
     */
    public function hasGlobalScope(string $class): bool
    {
        foreach ($this->project->classes()->lineage($class) as $name) {
            $info = $this->project->classes()->get($name);
            if ($info === null) {
                break;
            }
            foreach ($info->attributes() as $attribute) {
                if (Ast::shortName($attribute) === 'ScopedBy') {
                    return true;
                }
            }
            foreach ($info->traits() as $trait) {
                if (preg_match('/tenan|team|scoped|organi[sz]ation|workspace|multisite/i', (string) Ast::shortName($trait))) {
                    return true;
                }
            }
            foreach (['boot', 'booted'] as $method) {
                $node = $info->method($method);
                if ($node !== null && Ast::find($node, fn (Node $n) => Ast::callName($n) === 'addglobalscope') !== []) {
                    return true;
                }
            }
        }

        return false;
    }
}
