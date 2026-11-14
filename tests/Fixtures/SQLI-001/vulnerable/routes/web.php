<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;

Route::get('/report/{year}', function ($year) {
    return DB::select("select * from orders where year(created_at) = $year"); // expect: SQLI-001
});

Route::get('/count/{id}', function (int $id) {
    return DB::select("select count(*) from orders where user_id = $id");
});
