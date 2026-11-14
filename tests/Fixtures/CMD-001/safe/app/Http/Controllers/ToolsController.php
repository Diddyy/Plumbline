<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Process;

class ToolsController extends Controller
{
    public function convert(Request $request)
    {
        exec('convert '.escapeshellarg($request->input('file')).' out.pdf');
    }

    public function log(Request $request)
    {
        return Process::run(['git', 'log', $request->query('branch')])->output();
    }

    public function restart()
    {
        exec('php artisan queue:restart');
        system('du -sh '.storage_path());
    }

    public function count(int $limit)
    {
        return shell_exec("tail -n {$limit} storage/logs/laravel.log");
    }
}
