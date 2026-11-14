<?php

use App\Http\Controllers\AdminUserController;
use App\Http\Controllers\CommentController;
use App\Http\Controllers\DocumentController;
use App\Http\Controllers\PolicyHelperController;
use App\Http\Controllers\PostController;
use App\Http\Controllers\ProjectController;
use App\Http\Controllers\TaskController;
use App\Http\Controllers\TeamPostController;
use App\Models\Message;
use Illuminate\Support\Facades\Route;

Route::middleware('auth')->group(function () {
    Route::put('/posts/{post}', [PostController::class, 'update']);
    Route::delete('/posts/{post}', [PostController::class, 'destroy']);
    Route::put('/comments/{comment}', [CommentController::class, 'update'])->can('update', 'comment');
    Route::patch('/projects/{project}/archive', [ProjectController::class, 'archive']);
    Route::put('/tasks/{task}', [TaskController::class, 'update']);
    Route::resource('documents', DocumentController::class)->only(['update', 'destroy']);
    Route::delete('/polls/{poll}', [PolicyHelperController::class, 'destroy']);
    Route::post('/polls/{poll}/close', [PolicyHelperController::class, 'close']);
    Route::delete('/invites/{invite}', [PolicyHelperController::class, 'decline']);
    Route::delete('/my-polls/{poll}', [PolicyHelperController::class, 'rescoped']);
    Route::put('/team-posts/{teamPost}', [TeamPostController::class, 'update']);

    Route::delete('/messages/{message}', function (Message $message) {
        abort_unless($message->user()->is(auth()->user()), 403);
        $message->delete();
    });

    Route::middleware('admin')->group(function () {
        Route::put('/admin/users/{user}', [AdminUserController::class, 'update']);
    });
});

Route::middleware(['auth', 'role:editor'])->group(function () {
    Route::delete('/admin/posts/{post}', [PostController::class, 'forceDelete']);
});

Route::match(['get', 'post'], '/digest/unsubscribe/{user}', [App\Http\Controllers\AdminUserController::class, 'update'])
    ->middleware(['auth', 'signed']);
