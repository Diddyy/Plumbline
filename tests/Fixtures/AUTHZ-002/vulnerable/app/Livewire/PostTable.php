<?php

namespace App\Livewire;

use App\Models\Comment;
use App\Models\Invoice;
use App\Models\Post;
use Livewire\Component;

class PostTable extends Component
{
    public ?int $selectedInvoice = null;

    public function delete($id)
    {
        Post::find($id)->delete(); // expect: AUTHZ-002
    }

    public function publish(int $postId)
    {
        $post = Post::findOrFail($postId);
        $post->published = true;
        $post->save(); // expect: AUTHZ-002
    }

    public function approve(string $id)
    {
        Comment::where('id', $id)->update(['approved' => true]); // expect: AUTHZ-002
    }

    public function markPaid()
    {
        Invoice::whereKey($this->selectedInvoice)->first()?->update(['paid' => true]); // expect: AUTHZ-002
    }

    public function bulkDelete(array $ids)
    {
        Comment::destroy($ids); // expect: AUTHZ-002
    }

    public function render()
    {
        return view('livewire.post-table');
    }
}
