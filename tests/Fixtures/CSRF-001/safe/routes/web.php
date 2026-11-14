<?php

use App\Http\Controllers\MailgunController;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Facades\Route;

Route::post('/webhooks/mailgun', MailgunController::class)->withoutMiddleware(ValidateCsrfToken::class);
Route::get('/report', fn () => 'ok')->withoutMiddleware(ValidateCsrfToken::class);
