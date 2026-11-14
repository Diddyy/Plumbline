<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController extends Controller
{
    public function publish(Post $post)
    {
        $post->update(['published' => true]);
    }

    public function feature(Post $post)
    {
        $post->update(['featured' => true]);
    }

    public function destroy(Post $post)
    {
        $post->delete();
    }

    public function view(Post $post)
    {
        $post->increment('views');
    }
}
