<?php

namespace App\Http\Controllers;

use App\Models\TeamPost;
use Illuminate\Http\Request;

class TeamPostController extends Controller
{
    public function update(Request $request, TeamPost $teamPost)
    {
        // Route-model binding is already scoped to the current team by a global scope.
        $teamPost->update(['title' => $request->string('title')]);
    }
}
