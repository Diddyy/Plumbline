<?php

declare(strict_types=1);

namespace Plumbline\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Plumbline\Analysis\Ast;
use Plumbline\Finding;
use Plumbline\Project\PhpFile;
use Plumbline\Project\Project;
use Plumbline\Severity;

/**
 * Three narrow, name-driven checks:
 *  - a fast hash (md5/sha1/sha256) applied to a password
 *  - a predictable generator (rand, mt_rand, uniqid, time) used for a token, OTP or secret
 *  - == / === used to compare a token or signature (timing-unsafe; use hash_equals)
 */
final class WeakCrypto implements ProjectRule
{
    private const FAST_HASHES = ['md5', 'sha1', 'crc32', 'md5_file'];

    private const FAST_HASH_ALGOS = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'crc32', 'crc32b', 'xxh3', 'xxh64', 'xxh128'];

    private const PREDICTABLE = ['rand', 'mt_rand', 'uniqid', 'lcg_value', 'str_shuffle', 'array_rand', 'microtime', 'time', 'shuffle'];

    private const METADATA_SUFFIX = ['length', 'count', 'type', 'expires', 'expiry', 'at', 'ttl', 'lifetime', 'size', 'name', 'field', 'column', 'header', 'id', 'url', 'route', 'path', 'key'];

    public function meta(): RuleMeta
    {
        return new RuleMeta(
            'CRYPTO-001',
            'weak-crypto',
            'Weak hashing, randomness or comparison for secrets',
            Severity::Medium,
            'Passwords, tokens or signatures handled with fast hashes, predictable randomness or timing-unsafe comparison.',
            'CWE-327',
        );
    }

    public function check(Project $project): iterable
    {
        foreach ($project->phpFiles() as $file) {
            // Have I Been Pwned's k-anonymity API requires SHA-1 of the password by design.
            $pwnedCheck = stripos($file->code, 'pwnedpasswords') !== false;
            foreach (Ast::find($file->stmts(), fn (Node $n) => true) as $node) {
                if (! $pwnedCheck) {
                    yield from $this->fastPasswordHash($node, $file);
                }
                yield from $this->predictableSecret($node, $file);
                yield from $this->timingUnsafeCompare($node, $file);
            }
        }
    }

    /** @return iterable<Finding> */
    private function fastPasswordHash(Node $node, PhpFile $file): iterable
    {
        if (! $node instanceof Expr\FuncCall) {
            return;
        }
        $name = Ast::callName($node);
        $data = null;
        if (in_array($name, self::FAST_HASHES, true)) {
            $data = Ast::arg($node, 0);
        } elseif ($name === 'hash' && in_array(strtolower((string) Ast::stringValue(Ast::arg($node, 0))), self::FAST_HASH_ALGOS, true)) {
            $data = Ast::arg($node, 1);
        }
        if ($data === null) {
            return;
        }
        foreach ($this->subjects($data) as $subject) {
            $words = Ast::words($subject);
            if (array_intersect($words, ['password', 'passwd', 'pwd', 'passphrase']) !== [] && ! in_array(end($words), ['confirmation', 'length', 'reset'], true)) {
                yield $this->finding($file, $node, Severity::High, "{$name}() is used to hash a password (\${$subject}). Fast hashes can be brute-forced; use Hash::make() / password_hash().");

                return;
            }
        }
    }

    /** @return iterable<Finding> */
    private function predictableSecret(Node $node, PhpFile $file): iterable
    {
        $target = null;
        $value = null;
        if ($node instanceof Expr\Assign) {
            $target = Ast::subjectName($node->var);
            $value = $node->expr;
        } elseif ($node instanceof Node\ArrayItem && $node->key !== null) {
            $target = Ast::stringValue($node->key);
            $value = $node->value;
        }
        if ($target === null || $value === null || ! $this->isSecretName($target)) {
            return;
        }
        $generator = $this->predictableGenerator($value);
        if ($generator !== null) {
            yield $this->finding($file, $node, Severity::Medium, "'{$target}' is generated with {$generator}(), which is predictable. Use Str::random(40), random_int() or random_bytes().");
        }
    }

    /** @return iterable<Finding> */
    private function timingUnsafeCompare(Node $node, PhpFile $file): iterable
    {
        if (! $node instanceof Expr\BinaryOp\Identical && ! $node instanceof Expr\BinaryOp\Equal
            && ! $node instanceof Expr\BinaryOp\NotIdentical && ! $node instanceof Expr\BinaryOp\NotEqual) {
            return;
        }
        if ($this->isConstantish($node->left) || $this->isConstantish($node->right)) {
            return;
        }
        // Only an attacker-supplied value (header, bearer token, input) compared with a secret is a timing oracle.
        $fromRequest = $this->requestValueKey($node->left) ?? $this->requestValueKey($node->right);
        if ($fromRequest === null || in_array(strtolower($fromRequest), ['state', 'code'], true)) {
            return; // OAuth state/code are single-use; nothing to brute-force byte by byte.
        }
        foreach ([$node->left, $node->right] as $side) {
            $subject = Ast::subjectName($side);
            if ($subject === null) {
                continue;
            }
            $words = Ast::words($subject);
            if (in_array(end($words), self::METADATA_SUFFIX, true)) {
                continue;
            }
            if (array_intersect($words, ['token', 'signature', 'hmac', 'secret', 'apikey', 'nonce', 'otp']) !== []
                || (in_array('api', $words, true) && in_array('key', $words, true))) {
                yield $this->finding($file, $node, Severity::Low, "'{$subject}' is compared with ".($node instanceof Expr\BinaryOp\Equal || $node instanceof Expr\BinaryOp\NotEqual ? '==' : '===').", which leaks timing information. Use hash_equals(\$known, \$given).");

                return;
            }
        }
    }

    /**
     * When the expression reads the request ($request->header('X-Sig'), request('token'), ->bearerToken()),
     * the key it reads ('' when there is none); null otherwise.
     */
    private function requestValueKey(Expr $expr): ?string
    {
        foreach (Ast::find($expr, fn (Node $n) => $n instanceof Expr\MethodCall || $n instanceof Expr\FuncCall || $n instanceof Expr\ArrayDimFetch) as $node) {
            if ($node instanceof Expr\MethodCall && in_array(Ast::callName($node), ['header', 'bearertoken', 'input', 'query', 'post', 'get', 'cookie', 'server', 'string'], true)
                && (Ast::callName($node) === 'bearertoken' || $this->looksLikeRequest($node->var))) {
                return Ast::stringValue(Ast::arg($node, 0)) ?? '';
            }
            if ($node instanceof Expr\FuncCall && Ast::callName($node) === 'request' && Ast::arg($node, 0) !== null) {
                return Ast::stringValue(Ast::arg($node, 0)) ?? '';
            }
            if ($node instanceof Expr\ArrayDimFetch && $node->var instanceof Expr\Variable && in_array($node->var->name, ['_GET', '_POST', '_REQUEST', '_SERVER', '_COOKIE'], true)) {
                return Ast::stringValue($node->dim) ?? '';
            }
        }

        return null;
    }

    private function looksLikeRequest(Expr $expr): bool
    {
        return ($expr instanceof Expr\Variable && in_array($expr->name, ['request', 'req'], true))
            || ($expr instanceof Expr\FuncCall && Ast::callName($expr) === 'request')
            || ($expr instanceof Expr\PropertyFetch && Ast::subjectName($expr) === 'request');
    }

    private function isSecretName(string $name): bool
    {
        $words = Ast::words($name);
        if ($words === [] || in_array(end($words), self::METADATA_SUFFIX, true) && end($words) !== 'key') {
            return false;
        }
        if (array_intersect($words, ['token', 'secret', 'nonce', 'otp', 'salt', 'password', 'passcode', 'pin', 'apikey', 'csrf']) !== []) {
            return true;
        }
        if (in_array('key', $words, true) && array_intersect($words, ['api', 'secret', 'access', 'private', 'encryption', 'license', 'activation']) !== []) {
            return true;
        }

        return in_array('code', $words, true) && array_intersect($words, [
            'otp', 'verification', 'verify', 'reset', '2fa', 'twofactor', 'two', 'sms', 'email', 'login', 'auth', 'confirm',
            'confirmation', 'activation', 'invite', 'invitation', 'recovery', 'mfa', 'magic', 'security', 'access',
        ]) !== [];
    }

    private function predictableGenerator(Expr $expr): ?string
    {
        // Str::random(), random_int(), random_bytes() anywhere make it fine.
        $calls = Ast::find($expr, fn (Node $n) => $n instanceof Expr\FuncCall || $n instanceof Expr\StaticCall);
        foreach ($calls as $call) {
            $name = Ast::callName($call);
            if (in_array($name, ['random_int', 'random_bytes', 'openssl_random_pseudo_bytes', 'random', 'uuid', 'ulid', 'ordereduuid', 'password_hash', 'make', 'bcrypt'], true)) {
                return null;
            }
        }
        foreach ($calls as $call) {
            $name = Ast::callName($call);
            if ($call instanceof Expr\FuncCall && in_array($name, self::PREDICTABLE, true)) {
                return $name;
            }
        }

        return null;
    }

    /** @return list<string> names mentioned in an expression ($password, $request->password, $data['password']) */
    private function subjects(Expr $expr): array
    {
        $out = [];
        foreach (Ast::find($expr, fn (Node $n) => $n instanceof Expr\Variable || $n instanceof Expr\PropertyFetch || $n instanceof Expr\ArrayDimFetch || $n instanceof Expr\MethodCall) as $node) {
            $name = Ast::subjectName($node);
            if ($name !== null) {
                $out[] = $name;
            }
        }

        return $out;
    }

    private function isConstantish(Expr $expr): bool
    {
        return ($expr instanceof Node\Scalar && ! $expr instanceof Node\Scalar\InterpolatedString) || $expr instanceof Expr\ConstFetch || $expr instanceof Expr\ClassConstFetch
            || $expr instanceof Expr\Array_
            || ($expr instanceof Expr\FuncCall && in_array(Ast::callName($expr), ['count', 'strlen', 'mb_strlen', 'gettype', 'get_class'], true));
    }

    private function finding(PhpFile $file, Node $node, Severity $severity, string $message): Finding
    {
        $line = $node->getStartLine();

        return new Finding($this->meta()->id, $severity, $message, $file->relativePath, $line, $file->line($line));
    }
}
