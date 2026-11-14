<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class AdminUserController extends Controller
{
    public function update(Request $request, User $user)
    {
        // Behind the custom "admin" middleware.
        $user->update($request->only('name'));
    }
}
