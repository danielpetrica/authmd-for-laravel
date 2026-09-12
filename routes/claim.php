<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Http\Controllers\ClaimController;
use Illuminate\Support\Facades\Route;

Route::get('/claim', [ClaimController::class, 'show'])
    ->middleware(['web', 'auth'])
    ->name('claim.show');

Route::post('/claim/complete', [ClaimController::class, 'complete'])
    ->middleware(['web', 'auth'])
    ->name('claim.complete');

Route::get('/claim/success', [ClaimController::class, 'success'])
    ->middleware(['web', 'auth'])
    ->name('claim.success');
