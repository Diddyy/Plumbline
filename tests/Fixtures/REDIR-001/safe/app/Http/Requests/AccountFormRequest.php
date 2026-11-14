<?php

namespace App\Http\Requests;

use App\Rules\IsValidOriginUrl;
use Illuminate\Foundation\Http\FormRequest;

class AccountFormRequest extends FormRequest
{
    public function rules(): array
    {
        $rules = [
            'name' => 'required|max:255',
            '_from' => ['nullable', 'max:255', new IsValidOriginUrl()],
        ];
        $rules['iban'] = 'nullable';

        return $rules;
    }
}
