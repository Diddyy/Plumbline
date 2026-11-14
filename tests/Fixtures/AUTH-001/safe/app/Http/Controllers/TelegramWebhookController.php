<?php

namespace App\Http\Controllers;

use App\Models\Subscription;
use Illuminate\Http\Request;

class TelegramWebhookController extends Controller
{
    public function store(Request $request)
    {
        $channel = Subscription::where('chat_id', $request->input('message.chat.id'))->firstOrFail();
        $channel->active = true;
        $channel->save();
    }
}
