<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class InstallStoreRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return ['installation_key' => ['required', 'string', 'exists:installations,installation_key']];
    }
}
