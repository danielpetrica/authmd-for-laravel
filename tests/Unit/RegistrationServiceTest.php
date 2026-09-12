<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Enums\AgentRegistrationStatus;
use DanielPetrica\AuthMd\Enums\IdentityType;
use DanielPetrica\AuthMd\Events\AgentRegistered;
use DanielPetrica\AuthMd\Models\AgentAccessToken;
use DanielPetrica\AuthMd\Models\AgentRegistration;
use DanielPetrica\AuthMd\Services\RegistrationService;
use Illuminate\Support\Facades\Event;

beforeEach(function (): void {
    $this->service = new RegistrationService;
});

it('creates anonymous registration', function (): void {
    $registration = $this->service->createAnonymous(ip: '127.0.0.1');

    expect($registration)->toBeInstanceOf(AgentRegistration::class)
        ->and($registration->type)->toBe(IdentityType::Anonymous->value)
        ->and($registration->status)->toBe(AgentRegistrationStatus::Pending->value)
        ->and($registration->ip)->toBe('127.0.0.1')
        ->and($registration->registration_id)->toStartWith('reg_')
        ->and($registration->claim_token_hash)->not->toBeNull()
        ->and($registration->expires_at->isFuture())->toBeTrue();
});

it('creates service_auth registration', function (): void {
    $registration = $this->service->createServiceAuth(
        email: 'dev@example.com',
        ip: '127.0.0.1',
    );

    expect($registration->type)->toBe(IdentityType::ServiceAuth->value)
        ->and($registration->claim_email)->toBe('dev@example.com');
});

it('stores metadata on registration', function (): void {
    $metadata = ['user_agent' => 'TestAgent/1.0'];
    $registration = $this->service->createAnonymous(
        ip: '127.0.0.1',
        metadata: $metadata,
    );

    expect($registration->metadata)->toBe($metadata);
});

it('finds registration by claim token', function (): void {
    $registration = AgentRegistration::factory()->create([
        'claim_token_hash' => hash('sha256', 'clm_findme'),
    ]);

    $found = $this->service->findByClaimToken('clm_findme');

    expect($found)->not->toBeNull()
        ->and($found->id)->toBe($registration->id);
});

it('returns null for non-existent claim token', function (): void {
    $found = $this->service->findByClaimToken('clm_nonexistent');

    expect($found)->toBeNull();
});

it('marks registration as claimed', function (): void {
    Event::fake([AgentRegistered::class]);
    $registration = AgentRegistration::factory()->create();
    $this->service->markClaimed($registration, userId: 42);

    $registration->refresh();
    expect($registration->status)->toBe(AgentRegistrationStatus::Claimed->value)
        ->and($registration->user_id)->toBe(42)
        ->and($registration->claimed_at)->not->toBeNull();
});

it('revokes pre-claim tokens when claimed', function (): void {
    Event::fake([AgentRegistered::class]);
    $registration = AgentRegistration::factory()->create();

    AgentAccessToken::factory()->preClaim()->create([
        'agent_registration_id' => $registration->id,
    ]);
    AgentAccessToken::factory()->create([
        'agent_registration_id' => $registration->id,
    ]);

    $this->service->markClaimed($registration, userId: 42);

    expect($registration->accessTokens()->where('is_pre_claim', true)->where('revoked', true)->count())->toBe(1)
        ->and($registration->accessTokens()->where('is_pre_claim', false)->where('revoked', false)->count())->toBe(1);
});

it('marks registration as expired', function (): void {
    $registration = AgentRegistration::factory()->create();
    $this->service->markExpired($registration);

    $registration->refresh();
    expect($registration->status)->toBe(AgentRegistrationStatus::Expired->value);
});

it('expires unclaimed registrations', function (): void {
    AgentRegistration::factory()->create([
        'status' => AgentRegistrationStatus::Pending->value,
        'expires_at' => now()->subHour(),
    ]);
    AgentRegistration::factory()->create([
        'status' => AgentRegistrationStatus::Pending->value,
        'expires_at' => now()->addDay(),
    ]);

    $expired = $this->service->expireUnclaimed();

    expect($expired)->toBe(1);
});

it('dispatches AgentRegistered event on anonymous creation', function (): void {
    Event::fake([AgentRegistered::class]);

    $this->service->createAnonymous(ip: '127.0.0.1');

    Event::assertDispatched(AgentRegistered::class);
});

it('dispatches AgentRegistered event on service_auth creation', function (): void {
    Event::fake([AgentRegistered::class]);

    $this->service->createServiceAuth(email: 'dev@example.com', ip: '127.0.0.1');

    Event::assertDispatched(AgentRegistered::class);
});
