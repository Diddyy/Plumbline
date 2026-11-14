<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\Request;

class PostController extends Controller
{
    public function update(Request $request, Post $post)
    {
        $post->update($request->validate(['title' => 'required|string'])); // expect: AUTHZ-001

        return back();
    }

    public function destroy(Post $post)
    {
        $post->delete(); // expect: AUTHZ-001

        return redirect('/');
    }
}
