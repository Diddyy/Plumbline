<?php

namespace App\Http\Controllers;

use App\Models\Comment;
use Illuminate\Http\Request;

class CommentController extends Controller
{
    public function update(Request $request, Comment $comment)
    {
        $comment->title = $request->string('title');
        $comment->save(); // expect: AUTHZ-001

        return back();
    }
}
