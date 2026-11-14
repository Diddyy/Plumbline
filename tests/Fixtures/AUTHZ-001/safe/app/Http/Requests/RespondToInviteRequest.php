<?php

namespace App\Http\Requests;

use App\Rules\ValidInvite;
use Illuminate\Foundation\Http\FormRequest;

class RespondToInviteRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'invite' => ['required', new ValidInvite($this->user())],
        ];
    }
}
