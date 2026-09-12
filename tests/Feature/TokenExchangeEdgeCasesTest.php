<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Enums\AgentRegistrationStatus;
use DanielPetrica\AuthMd\Events\AgentTokenIssued;
use DanielPetrica\AuthMd\Models\AgentAccessToken;
use DanielPetrica\AuthMd\Models\AgentRegistration;
use DanielPetrica\AuthMd\Services\JwtSigningService;
use Illuminate\Support\Facades\Event;

it('creates access token record on exchange', function (): void {
    $jwt = JwtSigningService::make();
    AgentRegistration::factory()->create([
        'registration_id' => 'reg_record',
        'status' => AgentRegistrationStatus::Pending->value,
    ]);

    $assertion = $jwt->sign(['sub' => 'reg_record']);
    $this->postJson('/oauth2/token', [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion' => $assertion,
    ]);

    expect(AgentAccessToken::count())->toBe(1);
});

it('returns pre_claim scopes for unclaimed anonymous', function (): void {
    $jwt = JwtSigningService::make();
    AgentRegistration::factory()->create([
        'registration_id' => 'reg_pre',
        'status' => AgentRegistrationStatus::Pending->value,
        'type' => 'anonymous',
    ]);

    $assertion = $jwt->sign(['sub' => 'reg_pre']);
    $response = $this->postJson('/oauth2/token', [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion' => $assertion,
    ]);

    expect($response->json('scope'))->toBe('api.read');
});

it('dispatches AgentTokenIssued on exchange', function (): void {
    Event::fake([AgentTokenIssued::class]);
    $jwt = JwtSigningService::make();
    AgentRegistration::factory()->create([
        'registration_id' => 'reg_event',
        'status' => AgentRegistrationStatus::Pending->value,
    ]);

    $assertion = $jwt->sign(['sub' => 'reg_event']);
    $this->postJson('/oauth2/token', [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion' => $assertion,
    ]);

    Event::assertDispatched(AgentTokenIssued::class);
});

it('returns unsupported_grant_type for unknown grant', function (): void {
    $response = $this->postJson('/oauth2/token', [
        'grant_type' => 'unknown_grant',
    ]);

    $response->assertStatus(400)
        ->assertJsonPath('error', 'unsupported_grant_type');
});

it('claim grant returns post-claim token for claimed registration', function (): void {
    Event::fake();
    $registration = AgentRegistration::factory()->claimed()->create([
        'claim_token_hash' => hash('sha256', 'clm_claimed_success'),
        'claim_email' => 'dev@example.com',
    ]);

    $response = $this->postJson('/oauth2/token', [
        'grant_type' => 'urn:workos:agent-auth:grant-type:claim',
        'claim_token' => 'clm_claimed_success',
    ]);

    $response->assertOk()
        ->assertJsonStructure([
            'access_token',
            'token_type',
            'expires_in',
            'scope',
            'identity_assertion',
            'assertion_expires',
        ])
        ->assertJsonPath('scope', 'api.read api.write');
});

it('claim grant revokes pre-claim tokens', function (): void {
    Event::fake();
    $registration = AgentRegistration::factory()->claimed()->create([
        'claim_token_hash' => hash('sha256', 'clm_revoke_pre'),
    ]);

    AgentAccessToken::factory()->preClaim()->create([
        'agent_registration_id' => $registration->id,
    ]);

    $this->postJson('/oauth2/token', [
        'grant_type' => 'urn:workos:agent-auth:grant-type:claim',
        'claim_token' => 'clm_revoke_pre',
    ]);

    expect($registration->accessTokens()->where('is_pre_claim', true)->where('revoked', true)->count())->toBe(1);
});
