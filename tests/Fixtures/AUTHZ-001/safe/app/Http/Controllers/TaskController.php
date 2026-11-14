<?php

namespace App\Http\Controllers;

use App\Http\Requests\UpdateTaskRequest;
use App\Models\Task;

class TaskController extends Controller
{
    public function update(UpdateTaskRequest $request, Task $task)
    {
        $task->update($request->validated());
    }
}
