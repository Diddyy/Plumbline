<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;

class LoginController extends Controller
{
    public function next(Request $request)
    {
        return redirect($request->input('next')); // expect: REDIR-001
    }

    public function returnTo(Request $request)
    {
        $url = $request->query('return_url', '/');

        return redirect()->to($url); // expect: REDIR-001
    }

    public function slashOnly(Request $request)
    {
        $next = $request->input('next');
        if (str_starts_with($next, '/')) {
            return redirect($next); // expect: REDIR-001
        }
    }

    public function eitherBranch(Request $request)
    {
        $next = $request->input('next');
        if ($request->boolean('x') || str_starts_with($next, '/account/')) {
            return redirect($next); // expect: REDIR-001
        }
    }

    public function userinfoTrick(Request $request)
    {
        // https://app.test + '@evil.com' => https://app.test@evil.com
        return redirect(route('index').$request->input('_from')); // expect: REDIR-001
    }

    public function slashThenInput(Request $request)
    {
        // '/' + '/evil.com' => //evil.com
        return redirect('/'.$request->input('path')); // expect: REDIR-001
    }

    public function referer(Request $request)
    {
        return Redirect::away($request->header('referer')); // expect: REDIR-001
    }
}
