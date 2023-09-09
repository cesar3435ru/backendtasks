<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\TaskController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

//THIS WAY WORKS
// Route::middleware(['jwt.auth'])->group(function() {
//     Route::post('logout', [AuthController::class, 'logout']);
//     Route::post('refresh', [AuthController::class, 'refresh']);
//     Route::post('profile', [AuthController::class, 'userProfileInfo']);
//     Route::post('updateinfo', [AuthController::class, 'updateUser']);

// });

// Route::post('login', [AuthController::class, 'login']);
// Route::post('register', [AuthController::class, 'registerUser']);

//This way works better because my code looks cleaner
Route::controller(AuthController::class)->group(function () {
    Route::post('register', 'registerUser');
    Route::post('login', 'login');
    Route::post('logout', 'logout');
    Route::post('profile', 'userProfileInfo');
    Route::post('refresh', 'refresh');
    Route::post('updateinfo', 'updateUser');
});

Route::controller(TaskController::class)->group(function () {
    Route::post('addtask', 'addTask');
    Route::get('tasks', 'getAllTasksByUser');
    Route::get('tasks/{id}', 'getTaskById');
    Route::put('edittask/{id}', 'editTaskById');
    Route::put('taskdone/{id}', 'TaskDoneById');
    Route::delete('tasks/{id}', 'deleteTaskById');
});
