<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class UploadController extends Controller
{
    public function avatar(Request $request)
    {
        $file = $request->file('avatar');
        $file->store('avatars');
        $file->storeAs('avatars', $file->hashName());
        $file->storeAs('avatars', Str::uuid().'.'.$file->extension());
    }

    public function keepsName(Request $request)
    {
        $file = $request->file('avatar');
        $base = pathinfo($file->getClientOriginalName(), PATHINFO_FILENAME);
        $file->storeAs('avatars', Str::slug($base).'.'.$file->extension());
        $file->storeAs('avatars', "{$request->user()->id}.jpg");
    }

    public function allowlistedInHelper(Request $request)
    {
        $file = $request->file('asset');
        $this->ensureImage($file);
        $file->storeAs('assets', Str::random(16).'.'.strtolower($file->getClientOriginalExtension()), 'public');
    }

    public function validatedExtensions(Request $request)
    {
        $request->validate(['doc' => 'required|file|extensions:pdf,docx']);
        $file = $request->file('doc');
        $file->storeAs('docs', $file->getClientOriginalName());
    }

    public function privateDisk(Request $request)
    {
        $file = $request->file('doc');
        Storage::putFileAs('docs', $file, $file->getClientOriginalName(), 'private');
        // The default (local) disk isn't web-served either.
        $file->storeAs('docs', $file->getClientOriginalName());
        $file->move(storage_path('app/tmp'), $file->getClientOriginalName());
    }

    private function ensureImage($file): void
    {
        $extension = strtolower($file->getClientOriginalExtension());
        if (! in_array($extension, ['jpg', 'png', 'webp'], true)) {
            abort(422);
        }
    }

    public function chess(Request $request, $game)
    {
        // A game move, not a file move.
        $game->move($request->input('from'), $request->input('to'));
    }
}
