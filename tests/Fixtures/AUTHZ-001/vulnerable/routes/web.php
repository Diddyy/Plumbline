<?php

use App\Http\Controllers\CommentController;
use App\Http\Controllers\PostController;
use App\Models\Task;
use Illuminate\Support\Facades\Route;

Route::get('/', fn () => view('welcome'));

Route::middleware('auth')->group(function () {
    Route::put('/posts/{post}', [PostController::class, 'update']);
    Route::delete('/posts/{post}', [PostController::class, 'destroy']);
    Route::resource('comments', CommentController::class)->only(['update']);

    Route::delete('/tasks/{task}', function (Task $task) {
        $task->delete(); // expect: AUTHZ-001

        return back();
    });
});

Route::middleware(['auth', 'verified'])->prefix('team')->group(base_path('routes/team.php'));
