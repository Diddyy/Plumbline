<?php

namespace App\Http\Controllers;

use App\Models\Subscription;
use Illuminate\Http\Request;

class StripeWebhookController extends Controller
{
    public function __invoke(Request $request)
    {
        Subscription::where('stripe_id', $request->input('id'))->update(['status' => 'active']);
    }
}
