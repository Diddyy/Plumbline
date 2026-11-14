<?php

namespace App\Livewire;

use App\Models\Comment;
use App\Models\Invoice;
use App\Models\Post;
use App\Models\TeamTask;
use Illuminate\Support\Facades\Gate;
use Livewire\Attributes\Locked;
use Livewire\Component;

class PostTable extends Component
{
    #[Locked]
    public int $invoiceId;

    public Post $post;

    public function delete($id)
    {
        $post = Post::findOrFail($id);
        $this->authorize('delete', $post);
        $post->delete();
    }

    public function archive($id)
    {
        auth()->user()->posts()->findOrFail($id)->update(['archived' => true]);
    }

    public function approve($id)
    {
        Comment::where('id', $id)->where('user_id', auth()->id())->update(['approved' => true]);
    }

    public function gate($id)
    {
        $comment = Comment::findOrFail($id);
        Gate::authorize('update', $comment);
        $comment->update(['approved' => true]);
    }

    public function own($id)
    {
        $comment = Comment::findOrFail($id);
        abort_unless($comment->user_id === auth()->id(), 403);
        $comment->delete();
    }

    public function locked()
    {
        // #[Locked] can't be changed from the browser.
        Invoice::find($this->invoiceId)->update(['paid' => true]);
    }

    public function boundModel()
    {
        // Model-typed properties are locked by Livewire.
        $this->post->update(['title' => 'x']);
    }

    public function scoped($id)
    {
        TeamTask::find($id)->delete();
    }

    public function updatedSearch($value)
    {
        $this->resetPage();
    }

    public function mount($id)
    {
        $this->post = Post::findOrFail($id);
    }

    public function render()
    {
        return view('livewire.post-table');
    }
}
