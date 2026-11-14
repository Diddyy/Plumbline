<?php

namespace App\Http\Controllers;

use App\Models\Document;
use Illuminate\Http\Request;

class DocumentController extends Controller
{
    public function __construct()
    {
        $this->authorizeResource(Document::class, 'document');
    }

    public function update(Request $request, Document $document)
    {
        $document->update(['title' => $request->string('title')]);
    }

    public function destroy(Document $document)
    {
        $document->delete();
    }
}
