<?php

namespace App\Http\Controllers;

use App\Http\Requests\StorePostRequest;
use App\Models\Post;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;

class SearchController extends Controller
{
    public function bindings(Request $request)
    {
        $term = $request->input('q');

        return DB::select('select * from posts where title like ?', ['%'.$term.'%']);
    }

    public function rawWithBindings(Request $request)
    {
        return Post::whereRaw('lower(name) = ?', [strtolower($request->input('name'))])->get();
    }

    public function allowlistIf(Request $request)
    {
        $column = $request->query('sort');
        if (! in_array($column, ['name', 'created_at'], true)) {
            abort(400);
        }

        return Post::orderByRaw($column.' desc')->get();
    }

    public function allowlistAbort(Request $request)
    {
        $column = $request->input('col');
        abort_unless(in_array($column, ['a', 'b'], true), 422);

        return Post::orderByRaw($column)->get();
    }

    public function ternary(Request $request)
    {
        $direction = $request->input('dir') === 'asc' ? 'asc' : 'desc';

        return Post::orderByRaw("created_at $direction")->get();
    }

    public function ternaryAllowlist(Request $request)
    {
        $sort = $request->input('sort');
        $sort = in_array($sort, ['name', 'email'], true) ? $sort : 'id';

        return Post::orderByRaw($sort)->get();
    }

    public function matched(Request $request)
    {
        $column = match ($request->input('sort')) {
            'name' => 'name',
            default => 'id',
        };

        return Post::orderByRaw($column)->get();
    }

    public function validated(Request $request)
    {
        $data = $request->validate([
            'year' => 'required|integer',
            'sort' => ['required', Rule::in(['title', 'created_at'])],
        ]);

        return DB::select("select * from orders where year = {$data['year']} order by {$data['sort']}");
    }

    public function validatedThenInput(Request $request)
    {
        $request->validate(['page' => 'required|numeric']);

        return DB::select('select * from posts limit 10 offset '.$request->input('page'));
    }

    public function casts(Request $request)
    {
        $id = (int) $request->input('id');
        $limit = $request->integer('limit');

        return DB::select("select * from posts where id = $id limit $limit");
    }

    public function typedRouteParam(int $id)
    {
        return DB::select("select * from posts where id = $id");
    }

    public function boundModel(Post $post)
    {
        return DB::select("select * from comments where post_id = {$post->id}");
    }

    public function formRequest(StorePostRequest $request)
    {
        return DB::select('select * from categories where id = '.$request->input('category_id'));
    }

    public function reassigned(Request $request)
    {
        $sort = $request->input('sort');
        $sort = 'created_at';

        return Post::orderByRaw($sort)->get();
    }

    public function constants()
    {
        $table = config('database.archive_table');

        return DB::select("select * from {$table} where archived = 1");
    }
}
