<?php

// Nothing in bootstrap/app.php loads this file, so its middleware context is unknown
// and access-control rules must not guess.

use App\Http\Controllers\PostController;
use Illuminate\Support\Facades\Route;

Route::delete('/legacy/posts/{post}', [PostController::class, 'forceDelete']);
