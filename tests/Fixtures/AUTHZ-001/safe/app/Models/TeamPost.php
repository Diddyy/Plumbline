<?php

namespace App\Models;

use App\Models\Concerns\BelongsToTeam;
use Illuminate\Database\Eloquent\Model;

class TeamPost extends Model
{
    use BelongsToTeam;
}
