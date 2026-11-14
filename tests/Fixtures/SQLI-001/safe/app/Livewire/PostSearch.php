<?php

namespace App\Livewire;

use App\Models\Post;
use Livewire\Attributes\Locked;
use Livewire\Component;

class PostSearch extends Component
{
    public string $search = '';

    public int $year = 2024;

    #[Locked]
    public string $column = 'id';

    public function render()
    {
        return view('posts', [
            'posts' => Post::where('title', 'like', "%{$this->search}%")
                ->whereRaw("year(created_at) = {$this->year}")
                ->orderByRaw($this->column)
                ->get(),
        ]);
    }
}
