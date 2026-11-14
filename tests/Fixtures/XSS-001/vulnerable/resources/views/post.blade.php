<x-layout>
    <h1>Results for {!! request('q') !!}</h1> {{-- expect: XSS-001 --}}
    <article>{!! $post->body !!}</article> {{-- expect: XSS-001 --}}
    <section>{!! Str::markdown($post->summary) !!}</section> {{-- expect: XSS-001 --}}
    <p>{!! nl2br($comment->body) !!}</p> {{-- expect: XSS-001 --}}
    <p>{!! __('Welcome back, :name', ['name' => $user->name]) !!}</p> {{-- expect: XSS-001 --}}
    <input name="email" value="{!! old('email') !!}"> {{-- expect: XSS-001 --}}
    <p>{!! "Hello {$user->name}" !!}</p> {{-- expect: XSS-001 --}}
</x-layout>
<p>{!! request()->query('tab') !!}</p> {{-- expect: XSS-001 --}}
<p>{!! request()->user()->name !!}</p> {{-- expect: XSS-001 --}}
