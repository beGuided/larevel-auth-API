<?php

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
//use App\Http\Controllers\AuthController;
use App\Http\Controllers\Api\EmailVerificationController;
use App\Http\Controllers\Api\NewPasswordController;

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


Route::group(['prefix' => 'v1'], function () {
        
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/login', [AuthController::class, 'login']);

    Route::post('password/forgot-password', [NewPasswordController::class, 'forgotPassword']);
    Route::post('password/reset', [NewPasswordController::class, 'reset']);

});

 Route::group(  ['middleware'=> ['auth:sanctum'],  'prefix' => 'v1' ], function () {  
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/email/verify-email/{id}/{hash}', [AuthController::class, 'verifyEmail'])->name('verification.verify');
   
 });
         

Route::middleware('auth:sanctum','verified')->get('/user', function (Request $request) {
    return $request->user();
});
