<?php

namespace App\Http\Controllers;

use App\Http\Requests\InstallStoreRequest;
use App\Models\Project;
use App\Models\Message;
use Illuminate\Http\Request;

class InstallController extends Controller
{
    public function store(InstallStoreRequest $request)
    {
        Project::first()->update(['step' => 1]);
    }

    public function inline(Request $request)
    {
        $request->validate(['token' => 'required|exists:invites,token']);
        Message::where('token', $request->input('token'))->update(['read' => true]);
    }
}
