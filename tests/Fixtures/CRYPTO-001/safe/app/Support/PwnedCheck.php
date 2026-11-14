<?php

namespace App\Support;

use Illuminate\Support\Facades\Http;

class PwnedCheck
{
    public function isPwned(string $password): bool
    {
        $hash = strtoupper(sha1($password));
        $body = Http::get('https://api.pwnedpasswords.com/range/'.substr($hash, 0, 5))->body();

        return str_contains($body, substr($hash, 5));
    }
}
