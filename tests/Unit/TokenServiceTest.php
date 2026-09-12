<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Events\AgentTokenIssued;
use DanielPetrica\AuthMd\Events\AgentTokenRevoked;
use DanielPetrica\AuthMd\Models\AgentAccessToken;
use DanielPetrica\AuthMd\Models\AgentRegistration;
use DanielPetrica\AuthMd\Services\TokenService;
use Illuminate\Support\Facades\Event;

beforeEach(function (): void {
    $this->service = TokenService::make();
});

it('issues an access token', function (): void {
    Event::fake([AgentTokenIssued::class]);
    $registration = AgentRegistration::factory()->create();

    $token = $this->service->issue($registration);

    expect($token)->toStartWith('at_')
        ->and(AgentAccessToken::count())->toBe(1);

    Event::assertDispatched(AgentTokenIssued::class);
});

it('issues pre-claim token with correct scopes', function (): void {
    $registration = AgentRegistration::factory()->create();
    $this->service->issue($registration, isPreClaim: true);

    $dbToken = AgentAccessToken::first();
    expect($dbToken->scope)->toBe('api.read')
        ->and($dbToken->is_pre_claim)->toBeTrue();
});

it('issues post-claim token with correct scopes', function (): void {
    $registration = AgentRegistration::factory()->create();
    $this->service->issue($registration, isPreClaim: false);

    $dbToken = AgentAccessToken::first();
    expect($dbToken->scope)->toBe('api.read api.write')
        ->and($dbToken->is_pre_claim)->toBeFalse();
});

it('validates a valid token', function (): void {
    $registration = AgentRegistration::factory()->create();
    $plainToken = $this->service->issue($registration);

    $found = $this->service->validate($plainToken);

    expect($found)->not->toBeNull()
        ->and($found->id)->toBe($registration->id);
});

it('returns null for expired token', function (): void {
    $registration = AgentRegistration::factory()->create();
    $plainToken = $this->service->issue($registration);

    AgentAccessToken::where('token_hash', AgentAccessToken::hashToken($plainToken))
        ->update(['expires_at' => now()->subHour()]);

    $found = $this->service->validate($plainToken);

    expect($found)->toBeNull();
});

it('returns null for revoked token', function (): void {
    $registration = AgentRegistration::factory()->create();
    $plainToken = $this->service->issue($registration);

    $this->service->revoke($plainToken);

    $found = $this->service->validate($plainToken);

    expect($found)->toBeNull();
});

it('returns null for unknown token', function (): void {
    $found = $this->service->validate('at_nonexistent');

    expect($found)->toBeNull();
});

it('updates last_used_at on validation', function (): void {
    $registration = AgentRegistration::factory()->create();
    $plainToken = $this->service->issue($registration);

    $this->service->validate($plainToken);

    $token = AgentAccessToken::first();
    expect($token->last_used_at)->not->toBeNull();
});

it('revokes a token', function (): void {
    Event::fake([AgentTokenRevoked::class]);
    $registration = AgentRegistration::factory()->create();
    $plainToken = $this->service->issue($registration);

    $this->service->revoke($plainToken);

    $token = AgentAccessToken::first();
    expect($token->revoked)->toBeTrue();
    Event::assertDispatched(AgentTokenRevoked::class);
});

it('dispatches AgentTokenRevoked event on revoke', function (): void {
    Event::fake([AgentTokenRevoked::class]);
    $registration = AgentRegistration::factory()->create();
    $plainToken = $this->service->issue($registration);

    $this->service->revoke($plainToken);

    Event::assertDispatched(AgentTokenRevoked::class);
});
