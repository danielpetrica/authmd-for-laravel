<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Models\AgentRegistration;

it('stores IP address on registration', function (): void {
    $response = $this->postJson('/agent/identity', ['type' => 'anonymous']);

    $registration = AgentRegistration::where('registration_id', $response->json('registration_id'))->first();
    expect($registration->ip)->not->toBeNull();
});

it('sets correct expiry on registration', function (): void {
    $response = $this->postJson('/agent/identity', ['type' => 'anonymous']);

    $registration = AgentRegistration::where('registration_id', $response->json('registration_id'))->first();
    expect($registration->expires_at->isFuture())->toBeTrue();
});

it('returns registration_id with reg_ prefix', function (): void {
    $response = $this->postJson('/agent/identity', ['type' => 'anonymous']);

    expect($response->json('registration_id'))->toStartWith('reg_');
});

it('returns claim_token with clm_ prefix', function (): void {
    $response = $this->postJson('/agent/identity', ['type' => 'anonymous']);

    expect($response->json('claim_token'))->toStartWith('clm_');
});

it('returns identity_assertion as JWT', function (): void {
    $response = $this->postJson('/agent/identity', ['type' => 'anonymous']);

    $assertion = $response->json('identity_assertion');
    expect($assertion)->toContain('.')
        ->and(substr_count($assertion, '.'))->toBe(2); // header.payload.signature
});

it('anonymous registration includes pre_claim_scopes', function (): void {
    $response = $this->postJson('/agent/identity', ['type' => 'anonymous']);

    expect($response->json('pre_claim_scopes'))->toBe(['api.read']);
});

it('service_auth registration does not include pre_claim_scopes', function (): void {
    $response = $this->postJson('/agent/identity', [
        'type' => 'service_auth',
        'login_hint' => 'dev@example.com',
    ]);

    expect($response->json('pre_claim_scopes'))->toBeNull();
});

it('both types include post_claim_scopes', function (): void {
    $anon = $this->postJson('/agent/identity', ['type' => 'anonymous']);
    $service = $this->postJson('/agent/identity', [
        'type' => 'service_auth',
        'login_hint' => 'dev@example.com',
    ]);

    expect($anon->json('post_claim_scopes'))->toBe(['api.read', 'api.write'])
        ->and($service->json('post_claim_scopes'))->toBe(['api.read', 'api.write']);
});
