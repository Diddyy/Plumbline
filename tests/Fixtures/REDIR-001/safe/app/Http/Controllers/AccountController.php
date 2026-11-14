<?php

namespace App\Http\Controllers;

use App\Http\Requests\AccountFormRequest;

class AccountController extends Controller
{
    public function store(AccountFormRequest $request)
    {
        $from = $request->input('_from', '');

        return redirect(route('index').$from);
    }
}
