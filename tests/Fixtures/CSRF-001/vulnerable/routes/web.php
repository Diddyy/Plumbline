<?php

use App\Http\Controllers\SettingsController;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;
use Illuminate\Support\Facades\Route;

Route::post('/settings', [SettingsController::class, 'update'])->withoutMiddleware(VerifyCsrfToken::class); // expect: CSRF-001
