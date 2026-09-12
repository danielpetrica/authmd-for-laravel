<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Models\AgentAccessToken;
use DanielPetrica\AuthMd\Models\AgentRegistration;
use DanielPetrica\AuthMd\Services\TokenService;

it('valid returns registration', function (): void {
    $service = TokenService::make();
    $registration = AgentRegistration::factory()->create();
    $token = $service->issue($registration);

    $found = $service->validate($token);

    expect($found)->not->toBeNull()
        ->and($found->id)->toBe($registration->id);
});

it('expired token returns null', function (): void {
    $service = TokenService::make();
    $registration = AgentRegistration::factory()->create();
    $token = $service->issue($registration);

    AgentAccessToken::where('token_hash', AgentAccessToken::hashToken($token))
        ->update(['expires_at' => now()->subHour()]);

    expect($service->validate($token))->toBeNull();
});

it('revoked token returns null', function (): void {
    $service = TokenService::make();
    $registration = AgentRegistration::factory()->create();
    $token = $service->issue($registration);

    $service->revoke($token);

    expect($service->validate($token))->toBeNull();
});

it('unknown token returns null', function (): void {
    $service = TokenService::make();

    expect($service->validate('at_nonexistent'))->toBeNull();
});

it('updates last_used_at on successful validation', function (): void {
    $service = TokenService::make();
    $registration = AgentRegistration::factory()->create();
    $token = $service->issue($registration);

    $service->validate($token);

    $dbToken = AgentAccessToken::first();
    expect($dbToken->last_used_at)->not->toBeNull();
});
