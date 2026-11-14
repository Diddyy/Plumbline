<?php

namespace App\Http\Controllers;

use App\Models\Message;
use Illuminate\Http\Request;

class PublicDisputeController extends Controller
{
    public function store(Request $request)
    {
        Message::where('player_id', $request->integer('player_id'))->latest()->first()?->update(['disputed' => true]);
    }
}
