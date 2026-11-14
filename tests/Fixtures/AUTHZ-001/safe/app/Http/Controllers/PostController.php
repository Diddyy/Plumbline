<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class PostController extends Controller
{
    public function update(Request $request, Post $post)
    {
        $this->authorize('update', $post);
        $post->update($request->validate(['title' => 'required']));
    }

    public function destroy(Post $post)
    {
        Gate::authorize('delete', $post);
        $post->delete();
    }

    public function forceDelete(Post $post)
    {
        // Guarded by role:editor on the route.
        $post->forceDelete();
    }
}
