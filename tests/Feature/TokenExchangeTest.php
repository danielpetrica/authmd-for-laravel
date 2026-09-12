<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Enums\AgentRegistrationStatus;
use DanielPetrica\AuthMd\Models\AgentAccessToken;
use DanielPetrica\AuthMd\Models\AgentRegistration;
use DanielPetrica\AuthMd\Services\JwtSigningService;

it('exchanges identity assertion for access token', function (): void {
    $jwt = JwtSigningService::make();
    AgentRegistration::factory()->create([
        'registration_id' => 'reg_test123',
        'status' => AgentRegistrationStatus::Pending->value,
    ]);

    $assertion = $jwt->sign(['sub' => 'reg_test123']);

    $response = $this->postJson('/oauth2/token', [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion' => $assertion,
    ]);

    $response->assertOk()
        ->assertJsonStructure([
            'access_token',
            'token_type',
            'expires_in',
            'scope',
        ]);

    expect(AgentAccessToken::count())->toBe(1);
});

it('returns authorization_pending for unclaimed claim grant', function (): void {
    AgentRegistration::factory()->create([
        'claim_token_hash' => hash('sha256', 'clm_test'),
        'status' => AgentRegistrationStatus::Pending->value,
    ]);

    $response = $this->postJson('/oauth2/token', [
        'grant_type' => 'urn:workos:agent-auth:grant-type:claim',
        'claim_token' => 'clm_test',
    ]);

    $response->assertStatus(400)
        ->assertJsonPath('error', 'authorization_pending');
});

it('returns expired_token for expired registration', function (): void {
    AgentRegistration::factory()->expired()->create([
        'claim_token_hash' => hash('sha256', 'clm_expired'),
    ]);

    $response = $this->postJson('/oauth2/token', [
        'grant_type' => 'urn:workos:agent-auth:grant-type:claim',
        'claim_token' => 'clm_expired',
    ]);

    $response->assertStatus(400)
        ->assertJsonPath('error', 'expired_token');
});
