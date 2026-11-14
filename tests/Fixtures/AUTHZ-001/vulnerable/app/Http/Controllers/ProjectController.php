<?php

namespace App\Http\Controllers;

use App\Models\Project;

class ProjectController extends Controller
{
    public function archive(Project $project)
    {
        $project->update(['archived' => true]); // expect: AUTHZ-001

        return back();
    }
}
