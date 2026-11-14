<?php

namespace App\Http\Controllers;

use App\Http\Requests\RespondToInviteRequest;
use App\Models\Invite;
use App\Models\Poll;
use Illuminate\Http\Request;

class PolicyHelperController extends Controller
{
    public function destroy(Request $request, Poll $poll)
    {
        $this->ensureOwned($request->user(), $poll);
        $poll->delete();
    }

    public function close(Request $request, Poll $poll)
    {
        $this->guardPoll($request, $poll);
        $poll->update(['closed' => true]);
    }

    public function rescoped(Request $request, Poll $poll)
    {
        $poll = Poll::whereKey($poll->id)->where('user_id', $request->user()->id)->firstOrFail();
        $poll->delete();
    }

    public function decline(RespondToInviteRequest $request, Invite $invite)
    {
        $invite->delete();
    }

    private function ensureOwned($user, Poll $poll): void
    {
        abort_unless($poll->user_id === $user->id, 403);
    }

    private function guardPoll(Request $request, Poll $poll): void
    {
        if ($poll->owner_id !== $request->user()->id) {
            abort(403);
        }
    }
}
