<?php

namespace App\Livewire;

use App\Models\Post;
use Livewire\Attributes\Locked;
use Livewire\Component;

class PostSearch extends Component
{
    public string $search = '';

    #[Locked]
    public string $tenant = 'acme';

    public function render()
    {
        return view('posts', ['posts' => Post::whereRaw("title like '%{$this->search}%'")->get()]); // expect: SQLI-001
    }

    public function sortBy($column)
    {
        $this->posts = Post::orderByRaw($column)->get(); // expect: SQLI-001
    }

    public function scoped()
    {
        // #[Locked] properties cannot be changed from the browser.
        return Post::whereRaw("tenant = '{$this->tenant}'")->get();
    }
}
