<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Models\Task;
use Illuminate\Support\Facades\Auth;

class TaskController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
    }

    public function addTask(Request $request)
    {
        if (!Auth::check()) {
            return response()->json(['error' => 'No access baby'], 401);
        }

        $user = Auth::user();

        $validator = Validator::make($request->all(), [
            'name' => 'required | string | max:50',
            'desc' => 'required | string | max:70',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }


        $task = Task::create([
            'name' => $request->name,
            'desc' => $request->desc,
            'user_id' => $user->id
        ]);

        return response()->json(['task' => $task], 201);
    }

    public function getAllTasksByUser()
    {
        if (!Auth::check()) {
            return response()->json(['error' => 'No access'], 401);
        }

        $user = Auth::user();


        //It gets all tasks from the user who logged in and his info
        // $tasks = Task::with('user')
        //     ->where('user_id', $user->id)
        //     ->get();

        //It gets all tasks from the user who logged in 
        $tasks = Task::where('user_id', $user->id)->get();

        if (!$tasks) {
            return response()->json(['error' => 'No tasks'], 404);
        }

        return response()->json(['tasks' => $tasks], 200);
    }

    public function getTaskById($idT)
    {
        if (!Auth::check()) {
            return response()->json(['error' => 'No access'], 401);
        }

        $user = Auth::user();

        $task = Task::find($idT);

        if (!$task) {
            return response()->json(['error' => 'Task not found in DB'], 404);
        }

        if ($task->user_id !== $user->id) {
            return response()->json(['error' => 'Task does not belong to this user'], 403);
        }

        return response()->json(['task' => $task], 200);
    }


    public function editTaskById($idT, Request $request)
    {
        if (!Auth::check()) {
            return response()->json(['error' => 'No access'], 401);
        }

        $user = Auth::user();

        $task = Task::find($idT);

        if (!$task) {
            return response()->json(['error' => 'Task not found in DB'], 404);
        }

        if ($task->user_id !== $user->id) {
            return response()->json(['error' => 'Unauthorized! This task does not belong you.'], 403);
        }

        $validateData = $request->validate([
            'name' => 'required|string|max:50',
            'desc' => 'nullable|string|max:70',
        ]);

        $task->update($validateData);

        return response()->json(['message' => 'Task updated successfully'], 200);
    }

    public function TaskDoneById($idT, Request $request)
    {
        if (!Auth::check()) {
            return response()->json(['error' => 'No access'], 401);
        }

        $user = Auth::user();

        $task = Task::find($idT);

        if (!$task) {
            return response()->json(['error' => 'Task not found in DB'], 404);
        }

        if ($task->user_id !== $user->id) {
            return response()->json(['error' => 'Unauthorized! This task does not belong you.'], 403);
        }

        //Mark task as finished
        $task->update(['completed' => true]);


        return response()->json(['message' => 'Task updated successfully'], 200);
    }

    public function deleteTaskById($idT)
    {
        if (!Auth::check()) {
            return response()->json(['error' => 'No access'], 401);
        }

        $user = Auth::user();

        $task = Task::find($idT);

        if (!$task) {
            return response()->json(['error' => 'Task not found in DB'], 404);
        }

        if ($task->user_id !== $user->id) {
            return response()->json(['error' => 'Unauthorized! This task does not belong you.'], 403);
        }

        $task->delete();

        return response()->json(['message' => 'Task deleted successfully...'], 200);
    }


    public function getStatusTaskById($idT)
    {
        if (!Auth::check()) {
            return response()->json(['error' => 'No access'], 401);
        }

        $user = Auth::user();

        $task = Task::find($idT);

        if (!$task) {
            return response()->json(['error' => 'Task not found in DB'], 404);
        }

        if ($task->user_id !== $user->id) {
            return response()->json(['error' => 'Task does not belong to this user'], 403);
        }
        return response()->json(['task' => $task->completed], 200);
    }
}
