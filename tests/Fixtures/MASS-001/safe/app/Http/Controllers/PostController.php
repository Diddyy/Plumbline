<?php

namespace App\Http\Controllers;

use App\Models\Comment;
use App\Models\Post;
use Illuminate\Http\Request;

class PostController extends Controller
{
    public function harmlessFillable(Request $request)
    {
        // Comment only allows 'body': mass assignment is constrained.
        return Comment::create($request->all());
    }

    public function validatedData(Request $request)
    {
        $data = $request->validate(['title' => 'required', 'body' => 'required']);

        return Post::create($data);
    }

    public function onlyFields(Request $request)
    {
        return Post::create($request->only(['title', 'body']));
    }

    public function safeOnly(Request $request)
    {
        $request->user()->update($request->safe()->only(['name']));
    }

    public function explicitArray(Request $request)
    {
        Comment::where('id', 1)->update(['body' => $request->input('body')]);

        return Post::find(1)->update(['title' => $request->input('title')]);
    }

    public function singleValue(Request $request, Post $post)
    {
        $post->update(['title' => $request->string('title')]);
    }
}
