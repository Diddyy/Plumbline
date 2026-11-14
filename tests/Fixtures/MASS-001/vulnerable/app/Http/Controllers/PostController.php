<?php

namespace App\Http\Controllers;

use App\Models\Comment;
use App\Models\Post;
use App\Models\User;
use Illuminate\Http\Request;

class PostController extends Controller
{
    public function store(Request $request)
    {
        return Post::create($request->all()); // expect: MASS-001
    }

    public function update(Request $request, Post $post)
    {
        $post->update($request->except('_token')); // expect: MASS-001
    }

    public function profile(Request $request)
    {
        $request->user()->update($request->all()); // expect: MASS-001
    }

    public function bulk(Request $request)
    {
        Comment::where('post_id', 1)->update($request->input()); // expect: MASS-001
    }

    public function force(Request $request, Comment $comment)
    {
        $comment->forceFill($request->all())->save(); // expect: MASS-001
    }

    public function register(Request $request)
    {
        $user = new User($request->all()); // expect: MASS-001
        $user->save();
    }

    public function merged(Request $request)
    {
        return Post::create(array_merge($request->all(), ['user_id' => $request->user()->id])); // expect: MASS-001
    }

    public function viaVariable(Request $request)
    {
        $data = $request->all();
        $data['user_id'] = $request->user()->id;

        return Post::create($data); // expect: MASS-001
    }

    public function found(Request $request, int $id)
    {
        $post = Post::findOrFail($id);
        $post->fill($request->all()); // expect: MASS-001
        $post->save();
    }
}
