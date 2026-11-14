<?php

namespace App\Models\Concerns;

trait BelongsToTeam
{
    public static function bootBelongsToTeam(): void
    {
        static::addGlobalScope('team', fn ($query) => $query->where('team_id', auth()->user()->current_team_id));
    }
}
