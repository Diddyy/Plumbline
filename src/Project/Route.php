<?php

declare(strict_types=1);

namespace Plumbline\Project;

use PhpParser\Node;
use Plumbline\Analysis\Ast;

final class Route
{
    /** Middleware that proves the user is authenticated (or holds a signed link). */
    private const AUTH_PATTERN = '/^(auth(\.basic|\.basic\.once)?(:.*)?|verified|password\.confirm|signed(:.*)?|abilities:.*|ability:.*|can:.*|role:.*|roles:.*|permission:.*|role_or_permission:.*)$/i';

    /** Middleware that performs an authorization check, not just authentication. */
    private const AUTHZ_PATTERN = '/^(can|role|roles|permission|role_or_permission|abilities|ability):/i';

    /** Middleware that is known not to authenticate or authorize. */
    private const BENIGN = [
        'web', 'api', 'bindings', 'substitutebindings', 'csrf', 'precognitive', 'cors', 'json', 'auth.session',
        'cache.headers', 'throttle', 'guest', 'stateful', 'encryptcookies', 'startsession', 'sharederrorsfromsession',
        'addqueuedcookiestoresponse', 'handleinertiarequests', 'addlinkheadersforpreloadedassets', 'handleappearance',
        'locale', 'setlocale', 'localize', 'localization', 'trimstrings', 'convertemptystringstonull', 'treblle',
        'preventrequestsduringmaintenance', 'trustproxies', 'handlecors', 'validatepostsize', 'nocache', 'etag',
    ];

    public function __construct(
        /** @var list<string> upper-case HTTP verbs */
        public readonly array $verbs,
        public readonly string $uri,
        /** @var list<string> normalised, group-expanded middleware */
        public readonly array $middleware,
        /** @var list<string> */
        public readonly array $withoutMiddleware,
        /** @var list<string> Middleware written on the route or its groups (not from the web/api group contents). */
        public readonly array $declaredMiddleware,
        public readonly string $file,
        public readonly int $line,
        public readonly bool $contextKnown,
        public readonly ?string $controller,
        public readonly ?string $method,
        public readonly ?Node\FunctionLike $closure,
    ) {
    }

    public function changesState(): bool
    {
        return array_intersect($this->verbs, ['POST', 'PUT', 'PATCH', 'DELETE', 'ANY']) !== [];
    }

    public function hasAuthentication(): bool
    {
        foreach ($this->middleware as $middleware) {
            if (preg_match(self::AUTH_PATTERN, $middleware)) {
                return true;
            }
        }

        return false;
    }

    public function hasAuthorizationMiddleware(): bool
    {
        foreach ($this->middleware as $middleware) {
            if (preg_match(self::AUTHZ_PATTERN, $middleware)) {
                return true;
            }
        }

        return false;
    }

    /** A signed URL binds its parameters: /unsubscribe/{user}?signature=... can't be pointed at another user. */
    public function isSigned(): bool
    {
        foreach ($this->middleware as $middleware) {
            if ($middleware === 'signed' || str_starts_with($middleware, 'signed:')) {
                return true;
            }
        }

        return false;
    }

    public function isGuestOnly(): bool
    {
        return in_array('guest', $this->middleware, true) || array_filter($this->middleware, fn ($m) => str_starts_with($m, 'guest:')) !== [];
    }

    /**
     * Middleware written on the route that we don't recognise. Custom middleware ("admin",
     * "EnsureTeamMember") may well be an access check, so rules that reason about access stay quiet.
     *
     * @return list<string>
     */
    public function unknownMiddleware(): array
    {
        $out = [];
        foreach ($this->declaredMiddleware as $middleware) {
            $name = strtolower(explode(':', $middleware, 2)[0]);
            if (preg_match(self::AUTH_PATTERN, $middleware) || in_array($name, self::BENIGN, true)) {
                continue;
            }
            $out[] = $middleware;
        }

        // Custom group middleware named after this route's section (InstallationMiddleware for
        // /installation/...) most likely gates it, even though it was added to the whole group.
        $section = strtolower(explode('/', trim($this->uri, '/'))[0]);
        if (strlen($section) >= 4 && ! str_starts_with($section, '{')) {
            foreach (array_diff($this->middleware, $this->declaredMiddleware) as $member) {
                $name = strtolower(explode(':', $member, 2)[0]);
                if (! in_array($name, self::BENIGN, true) && str_contains(str_replace(['-', '_'], '', $name), str_replace(['-', '_'], '', $section))) {
                    $out[] = $member;
                }
            }
        }

        return $out;
    }

    public function describe(): string
    {
        $verb = implode('|', array_values(array_diff($this->verbs, ['HEAD'])));
        $action = $this->controller !== null
            ? ' ('.Ast::shortName($this->controller).'@'.$this->method.')'
            : '';

        return $verb.' /'.ltrim($this->uri, '/').$action;
    }
}
