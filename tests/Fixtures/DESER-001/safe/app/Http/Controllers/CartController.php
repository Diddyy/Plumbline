<?php

namespace App\Http\Controllers;

use App\Models\Cart;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class CartController extends Controller
{
    public function restore(Request $request)
    {
        $plain = unserialize($request->cookie('cart'), ['allowed_classes' => false]);
        $allowlisted = unserialize($request->input('cart'), ['allowed_classes' => [Cart::class]]);
        $cached = unserialize(Cache::get('cart'));

        return json_decode($request->input('state'), true);
    }
}
