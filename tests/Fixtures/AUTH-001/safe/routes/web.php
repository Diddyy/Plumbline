<?php

use App\Http\Controllers\ContactController;
use App\Http\Controllers\InviteController;
use App\Http\Controllers\ModernPostController;
use App\Http\Controllers\PostController;
use App\Http\Controllers\StripeWebhookController;
use App\Models\Poll;
use App\Models\Subscription;
use Illuminate\Support\Facades\Route;

// Public, but only creates new records.
Route::post('/contact', [ContactController::class, 'store']);

// Machine-to-machine and auth flows.
Route::post('/webhooks/stripe', StripeWebhookController::class);
Route::post('/unsubscribe/{token}', function (string $token) {
    Subscription::where('token', $token)->firstOrFail()->delete();
});

// Protected in other ways.
Route::middleware('auth')->post('/posts/{post}/publish', [PostController::class, 'publish']);
Route::post('/posts/{post}/feature', [PostController::class, 'feature'])->middleware('auth:sanctum');
Route::middleware('signed')->post('/invites/{invite}/accept', [InviteController::class, 'accept']);
Route::middleware('ensure.team.member')->delete('/posts/{post}', [PostController::class, 'destroy']);
Route::put('/modern/posts/{post}', [ModernPostController::class, 'update']);

Route::post('/polls/{poll}/vote', function (Poll $poll) {
    if (! auth()->check()) {
        abort(403);
    }
    $poll->increment('votes');
});

// GET routes are not checked by this rule.
Route::get('/posts/{post}/view', [PostController::class, 'view']);

Route::post('/install', [App\Http\Controllers\InstallController::class, 'store']);
Route::post('/messages/read', [App\Http\Controllers\InstallController::class, 'inline']);
Route::post('/disputes/{team}', [App\Http\Controllers\PublicDisputeController::class, 'store']);

// Gated by InstallationMiddleware, appended to the whole web group.
Route::delete('/installation/{id}', function ($id) {
    App\Models\Project::find($id)->update(['completed' => false]);
});

Route::post('/telegram', [App\Http\Controllers\TelegramWebhookController::class, 'store']);
