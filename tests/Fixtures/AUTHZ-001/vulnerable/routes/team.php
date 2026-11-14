<?php

use App\Http\Controllers\ProjectController;
use Illuminate\Support\Facades\Route;

Route::patch('/projects/{project}/archive', [ProjectController::class, 'archive']);
