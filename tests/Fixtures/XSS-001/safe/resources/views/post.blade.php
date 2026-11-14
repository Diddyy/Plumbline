<form method="POST">
    {!! csrf_field() !!}
    {!! method_field('PUT') !!}
</form>

{!! $posts->links() !!}

<div {!! $attributes->merge(['class' => 'card']) !!}>
    {!! $slot !!}
</div>

<p>{!! __('auth.failed') !!}</p>
<p>{!! nl2br(e($comment->body)) !!}</p>
<section>{!! Str::markdown($post->body, ['html_input' => 'strip', 'allow_unsafe_links' => false]) !!}</section>
<p>{!! '<br>' !!}</p>
<p>{{ $escaped }}</p>

{{-- {!! $commentedOut->html !!} --}}

@verbatim
    <div>{!! $inVerbatim !!}</div>
@endverbatim
<td>{!! format_amount_by_symbol($row['amount'], $currency->symbol, 2) !!}</td>
<div>{!! ExpandedForm::text('description') !!}</div>
<div>{!! $user->renderBadge() !!}</div>
<p>{!! __('See the :startTag staff page :endTag.', ['startTag' => '<a href="/staff">', 'endTag' => '</a>']) !!}</p>
<script>window.user = {!! json_encode(App\Services\ProfileService::get(request()->user()->profile_id)) !!};</script>
