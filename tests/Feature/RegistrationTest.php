<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Enums\AgentRegistrationStatus;
use DanielPetrica\AuthMd\Enums\IdentityType;
use DanielPetrica\AuthMd\Events\AgentRegistered;
use DanielPetrica\AuthMd\Models\AgentRegistration;
use Illuminate\Support\Facades\Event;

it('registers an anonymous agent', function (): void {
    $response = $this->postJson('/agent/identity', ['type' => 'anonymous']);

    $response->assertOk()
        ->assertJsonStructure([
            'registration_id',
            'registration_type',
            'identity_assertion',
            'claim_token',
        ]);

    $registration = AgentRegistration::where('registration_id', $response->json('registration_id'))->first();

    expect($registration)->not->toBeNull()
        ->and($registration->type)->toBe(IdentityType::Anonymous->value)
        ->and($registration->status)->toBe(AgentRegistrationStatus::Pending->value)
        ->and($registration->claim_token_hash)->not->toBeNull();
});

it('registers a service_auth agent', function (): void {
    $response = $this->postJson('/agent/identity', [
        'type' => 'service_auth',
        'login_hint' => 'dev@example.com',
    ]);

    $response->assertOk()
        ->assertJsonPath('registration_type', 'service_auth');

    $registration = AgentRegistration::where('registration_id', $response->json('registration_id'))->first();

    expect($registration->claim_email)->toBe('dev@example.com');
});

it('dispatches AgentRegistered event', function (): void {
    Event::fake([AgentRegistered::class]);

    $this->postJson('/agent/identity', ['type' => 'anonymous']);

    Event::assertDispatched(AgentRegistered::class);
});

it('validates type parameter', function (): void {
    $this->postJson('/agent/identity', ['type' => 'invalid'])
        ->assertUnprocessable();
});

it('requires login_hint for service_auth', function (): void {
    $this->postJson('/agent/identity', ['type' => 'service_auth'])
        ->assertUnprocessable();
});
