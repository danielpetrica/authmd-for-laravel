<?php

use DanielPetrica\AuthMd\Http\Controllers\AgentIdentityController;
use DanielPetrica\AuthMd\Http\Controllers\TokenController;
use Illuminate\Support\Facades\Route;

Route::post('/agent/identity', [AgentIdentityController::class, 'store'])
    ->middleware(['throttle:agent-auth']);

Route::post('/agent/identity/claim', [AgentIdentityController::class, 'claim'])
    ->middleware(['throttle:agent-auth']);

Route::post('/oauth2/token', [TokenController::class, 'token']);
Route::post('/oauth2/revoke', [TokenController::class, 'revoke']);
