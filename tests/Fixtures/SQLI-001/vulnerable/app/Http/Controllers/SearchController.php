<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class SearchController extends Controller
{
    public function index(Request $request)
    {
        $term = $request->input('q');

        return DB::select("select * from posts where title like '%$term%'"); // expect: SQLI-001
    }

    public function sort(Request $request)
    {
        $column = $request->query('sort', 'created_at');

        return Post::query()->orderByRaw($column.' desc')->get(); // expect: SQLI-001
    }

    public function helper()
    {
        return Post::whereRaw('name = "'.request('name').'"')->get(); // expect: SQLI-001
    }

    public function show(string $slug)
    {
        return DB::select('select * from posts where slug = \''.$slug.'\''); // expect: SQLI-001
    }

    public function expression(Request $request)
    {
        $field = $request->string('field')->trim();

        return DB::table('posts')->select(DB::raw("count(*) as {$field}"))->get(); // expect: SQLI-001
    }

    public function branch(Request $request)
    {
        $order = 'id';
        if ($request->has('order')) {
            $order = $request->get('order');
        }

        return Post::query()->orderByRaw($order)->get(); // expect: SQLI-001
    }

    public function loop(Request $request)
    {
        foreach ($request->input('ids', []) as $id) {
            DB::statement("delete from posts where id = $id"); // expect: SQLI-001
        }
    }

    public function formatted(Request $request)
    {
        $sql = sprintf("select * from users where email = '%s'", $request->email);

        return DB::select($sql); // expect: SQLI-001
    }

    public function connection(Request $request)
    {
        return DB::connection('reporting')->select('select * from t where k = '.$request->input('k')); // expect: SQLI-001
    }

    public function validatedButLoose(Request $request)
    {
        $data = $request->validate(['name' => 'required|string|max:50']);

        return DB::select("select * from users where name = '{$data['name']}'"); // expect: SQLI-001
    }

    public function blocklistIsNotAnAllowlist(Request $request)
    {
        $column = $request->input('col');
        abort_if(in_array($column, ['password'], true), 422);

        return Post::orderByRaw($column)->get(); // expect: SQLI-001
    }

    public function header(Request $request)
    {
        return Post::query()->havingRaw('count(*) > '.$request->header('X-Min'))->get(); // expect: SQLI-001
    }
}
