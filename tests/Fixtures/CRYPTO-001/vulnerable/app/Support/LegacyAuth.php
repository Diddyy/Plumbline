<?php

namespace App\Support;

use Illuminate\Http\Request;

class LegacyAuth
{
    public function check(string $password, string $stored): bool
    {
        return md5($password) === $stored; // expect: CRYPTO-001
    }

    public function digest($user): string
    {
        return sha1($user->password.'pepper'); // expect: CRYPTO-001
    }

    public function sha256(array $data): string
    {
        return hash('sha256', $data['password']); // expect: CRYPTO-001
    }

    public function resetToken(): string
    {
        $resetToken = md5(uniqid()); // expect: CRYPTO-001

        return $resetToken;
    }

    public function otp(): int
    {
        $otp = rand(100000, 999999); // expect: CRYPTO-001

        return $otp;
    }

    public function keys(): array
    {
        return [
            'api_key' => str_shuffle('abcdefghijklmnopqrstuvwxyz0123456789'), // expect: CRYPTO-001
            'verification_code' => mt_rand(1000, 9999), // expect: CRYPTO-001
        ];
    }

    public function webhook(Request $request, string $secret): void
    {
        $expected = hash_hmac('sha256', $request->getContent(), $secret);
        if ($request->header('X-Signature') !== $expected) { // expect: CRYPTO-001
            abort(401);
        }
    }

    public function apiToken(Request $request, $user): bool
    {
        return $user->api_token == $request->bearerToken(); // expect: CRYPTO-001
    }
}
