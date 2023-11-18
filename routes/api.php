<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::controller(\App\Http\Controllers\UserController::class)->prefix('user')->group(function (){
    Route::post('create', 'create');
    Route::post('auth', 'auth');
    Route::post('registration', 'register');
    Route::post('anonymous/auth', 'signInAnonymously');
    Route::post('verify', 'verifyToken');
    Route::get('all', 'getUsers');
    Route::post('social', 'socialLogin');
});
