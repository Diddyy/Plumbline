<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class UploadController extends Controller
{
    public function avatar(Request $request)
    {
        $file = $request->file('avatar');
        $file->storeAs('avatars', $file->getClientOriginalName(), 'public'); // expect: UPLOAD-001
    }

    public function document(Request $request)
    {
        $request->file('doc')->move(public_path('uploads'), $request->file('doc')->getClientOriginalName()); // expect: UPLOAD-001
    }

    public function named(Request $request)
    {
        Storage::disk('public')->putFileAs('docs', $request->file('doc'), $request->input('filename')); // expect: UPLOAD-001
    }

    public function prefixed(Request $request)
    {
        $file = $request->file('image');
        $name = time().'_'.$file->getClientOriginalName();
        $file->storeAs('images', $name, ['disk' => 'public']); // expect: UPLOAD-001
    }

    public function publicly(Request $request)
    {
        $file = $request->file('image');
        $file->storePubliclyAs('images', $file->getClientOriginalName()); // expect: UPLOAD-001
    }
}
