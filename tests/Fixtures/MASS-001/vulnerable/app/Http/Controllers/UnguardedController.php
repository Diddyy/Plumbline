<?php

namespace App\Http\Controllers;

use App\Models\Comment;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class UnguardedController extends Controller
{
    public function store(Request $request)
    {
        // Not a model write, even though Model::unguard() is on.
        $validator = Validator::make($request->all(), ['body' => 'required']);
        $this->service->update($request->all());

        return Comment::create($request->all()); // expect: MASS-001
    }

    public function relation(Request $request)
    {
        $request->user()->comments()->create($request->all()); // expect: MASS-001
    }
}
