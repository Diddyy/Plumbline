<?php

namespace App\Support;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class ModernAuth
{
    public function hash(string $password): string
    {
        return Hash::make($password).password_hash($password, PASSWORD_DEFAULT);
    }

    public function gravatar($user): string
    {
        return 'https://www.gravatar.com/avatar/'.md5(strtolower($user->email));
    }

    public function cacheKey(array $filters): string
    {
        return sha1(json_encode($filters));
    }

    public function tokens(): array
    {
        $token = Str::random(60);
        $code = random_int(100000, 999999);
        $colorCode = rand(0, 255);
        $tokenExpiresAt = time() + 3600;
        $passwordLength = mt_rand(12, 16);

        return ['token' => $token, 'otp' => random_int(100000, 999999), 'seed' => mt_rand()];
    }

    public function oauth(Request $request, array $stateData, $latest, string $digest): bool
    {
        // OAuth state is single-use; a cache digest isn't attacker-supplied.
        return $stateData['token'] === $request->query('state')
            && $latest->input_digest === $digest;
    }

    public function compare(Request $request, ?string $token, string $type): bool
    {
        $expected = hash_hmac('sha256', $request->getContent(), 'secret');

        return hash_equals($expected, (string) $request->header('X-Signature'))
            && $token !== null
            && $request->user()->token_type === $type
            && $type === 'bearer';
    }
}
