<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Process;

class ToolsController extends Controller
{
    public function convert(Request $request)
    {
        $file = $request->input('file');
        exec("convert $file out.pdf"); // expect: CMD-001
    }

    public function ping(Request $request)
    {
        return shell_exec('ping -c 1 '.$request->host); // expect: CMD-001
    }

    public function list(Request $request)
    {
        return `ls {$request->input('dir')}`; // expect: CMD-001
    }

    public function log(Request $request)
    {
        return Process::run('git log '.$request->query('branch'))->output(); // expect: CMD-001
    }

    public function archive(string $name)
    {
        system('tar -czf /tmp/'.$name.'.tgz storage/app'); // expect: CMD-001
    }
}
