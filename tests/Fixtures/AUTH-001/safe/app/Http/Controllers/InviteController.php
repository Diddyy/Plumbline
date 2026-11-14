<?php

namespace App\Http\Controllers;

use App\Models\Invite;

class InviteController extends Controller
{
    public function accept(Invite $invite)
    {
        $invite->update(['accepted' => true]);
    }
}
