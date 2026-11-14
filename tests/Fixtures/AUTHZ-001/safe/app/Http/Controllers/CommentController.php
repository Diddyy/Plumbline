<?php

namespace App\Http\Controllers;

use App\Models\Comment;
use Illuminate\Http\Request;

class CommentController extends Controller
{
    public function update(Request $request, Comment $comment)
    {
        // Authorized by ->can('update', 'comment') on the route.
        $comment->update(['title' => $request->string('title')]);
    }
}
