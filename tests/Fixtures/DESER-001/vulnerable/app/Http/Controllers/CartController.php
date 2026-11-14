<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class CartController extends Controller
{
    public function restore(Request $request)
    {
        $cart = unserialize($request->cookie('cart')); // expect: DESER-001

        $state = base64_decode($request->input('state'));

        return unserialize($state); // expect: DESER-001
    }

    public function permissive(Request $request)
    {
        return unserialize($request->getContent(), ['allowed_classes' => true]); // expect: DESER-001
    }
}
