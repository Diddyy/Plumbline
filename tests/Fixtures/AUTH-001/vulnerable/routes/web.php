<?php

use App\Http\Controllers\PostController;
use App\Models\Comment;
use App\Models\Project;
use Illuminate\Support\Facades\Route;

Route::post('/posts/{post}/publish', [PostController::class, 'publish']);

Route::delete('/comments/{id}', function ($id) {
    Comment::findOrFail($id)->delete(); // expect: AUTH-001
});

Route::post('/projects/{id}/close', function ($id) {
    $project = Project::find($id);
    $project->status = 'closed';
    $project->save(); // expect: AUTH-001
});

Route::middleware('throttle:10,1')->group(function () {
    Route::put('/posts/{post}', [PostController::class, 'update']);
});

Route::post('/players/{id}/flag', function ($id) {
    App\Models\Comment::where('player_id', $id)->latest()->first()?->update(['flagged' => true]); // expect: AUTH-001
});
