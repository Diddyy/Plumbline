<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\Request;

class PostController extends Controller
{
    public function publish(Post $post)
    {
        $post->update(['published' => true]); // expect: AUTH-001

        return back();
    }

    public function update(Request $request, Post $post)
    {
        $post->update($request->only('title')); // expect: AUTH-001
    }
}
