<?php

use Illuminate\Http\Request;

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

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});
////////////////////////////////////////Admin login///////////////////////////////////////////////////////////////////////////
Route::group([

    'middleware' => 'api',
    'prefix' => 'admin'

], function ($router) {
    /* Admin */
    
    Route::post('adminLogin', 'authcontroller@adminLogin');
    Route::post('admins', 'authcontroller@admins');
    Route::delete('destroy/{id}', 'authcontroller@destroy');
    Route::delete('trached/{id}', 'authcontroller@trached');
    Route::delete('cancel_trached/{id}', 'authcontroller@cancel_trached');

    Route::post('adminRegister', 'authcontroller@adminRegister');
    Route::post('editAdmin/{id}', 'authcontroller@editAdmin');


    Route::post('register', 'authcontroller@register')->name('register');
    Route::post('logout', 'authcontroller@logout');
    Route::post('refresh', 'authcontroller@refresh');
    Route::post('me', 'authcontroller@me');
    Route::post('getRoles/{id}', 'authcontroller@getRoles');

});
///////////////////////////////End Admin Api//////////////////////////////////////////////////////////////////////////////////////
Route::post('register', 'UserController@register');
Route::post('login', 'UserController@authenticate');
Route::get('open', 'DataController@open');

Route::group(['middleware' => ['jwt.verify']], function() {
    Route::get('user', 'UserController@getAuthenticatedUser');
    Route::get('closed', 'DataController@closed');
});