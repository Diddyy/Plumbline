<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Str;

class LoginController extends Controller
{
    public function done(Request $request)
    {
        if ($request->boolean('remember')) {
            return redirect()->intended('/dashboard');
        }

        return redirect()->route('home');
    }

    public function same(Request $request)
    {
        return redirect($request->fullUrl());
    }

    public function fixed()
    {
        return redirect('/home');
    }

    public function previous()
    {
        return back();
    }

    public function prefixGuarded(Request $request)
    {
        $redirect = $request->input('_redirect');
        if ($redirect && str_starts_with($redirect, '/players/')) {
            return redirect($redirect);
        }

        return back();
    }

    public function earlyReturn(Request $request)
    {
        $next = $request->query('next');
        if (! Str::startsWith($next, config('app.url'))) {
            abort(400);
        }

        return redirect()->to($next);
    }

    public function devOnly(Request $request)
    {
        if (app()->environment('local')) {
            return redirect($request->query('path'));
        }

        return back();
    }

    public function localPaths(Request $request, string $id, string $username)
    {
        if ($request->boolean('a')) {
            return redirect('/i/web/post/'.$id);
        }
        if ($request->boolean('b')) {
            return redirect("/settings/{$request->input('tab')}");
        }
        if ($request->boolean('c')) {
            return redirect(route('home').'/'.$request->input('section'));
        }

        return redirect('/'.$username);
    }

    public function hostChecked(Request $request)
    {
        $returnUrl = $request->input('_return');
        $intended = parse_url($returnUrl);
        $sameOrigin = ($intended['host'] ?? '') === parse_url(url('/'), PHP_URL_HOST);

        return $sameOrigin ? redirect($returnUrl) : redirect('/');
    }

    public function fixedHost(Request $request)
    {
        $key = $request->route('key');

        return redirect()->away("https://www.dropbox.com/oauth2/authorize?client_id=$key&response_type=code");
    }

    public function customScheme(Request $request)
    {
        $ut = $request->input('ut');
        $url = 'pixelfed://confirm-account/'.$ut.'?'.http_build_query(['ut' => $ut]);

        return redirect()->away($url);
    }

    public function ternaryGuard(Request $request)
    {
        $redirect = $request->input('_redirect');

        return ($redirect && str_starts_with($redirect, '/players/')) ? redirect($redirect) : back();
    }

    public function allowlisted(Request $request)
    {
        $target = $request->input('to');
        $target = in_array($target, ['/billing', '/settings'], true) ? $target : '/';

        return redirect($target);
    }
}
