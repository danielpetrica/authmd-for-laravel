<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Models\AgentRegistration;

it('rejects claim with expired registration', function (): void {
    AgentRegistration::factory()->create([
        'claim_token_hash' => hash('sha256', 'clm_expired'),
        'expires_at' => now()->subHour(),
    ]);

    $response = $this->postJson('/agent/identity/claim', [
        'claim_token' => 'clm_expired',
        'email' => 'dev@example.com',
    ]);

    $response->assertStatus(400)
        ->assertJsonPath('error', 'claim_expired');
});

it('rejects claim with already claimed registration', function (): void {
    AgentRegistration::factory()->claimed()->create([
        'claim_token_hash' => hash('sha256', 'clm_claimed'),
    ]);

    $response = $this->postJson('/agent/identity/claim', [
        'claim_token' => 'clm_claimed',
        'email' => 'dev@example.com',
    ]);

    $response->assertStatus(400)
        ->assertJsonPath('error', 'claimed_or_in_flight');
});

it('rejects claim with non-existent token', function (): void {
    $response = $this->postJson('/agent/identity/claim', [
        'claim_token' => 'clm_nonexistent',
        'email' => 'dev@example.com',
    ]);

    $response->assertStatus(400)
        ->assertJsonPath('error', 'invalid_claim_token');
});

it('stores claim_email on registration', function (): void {
    AgentRegistration::factory()->create([
        'claim_token_hash' => hash('sha256', 'clm_email'),
    ]);

    $this->postJson('/agent/identity/claim', [
        'claim_token' => 'clm_email',
        'email' => 'dev@example.com',
    ]);

    $registration = AgentRegistration::where('claim_token_hash', hash('sha256', 'clm_email'))->first();
    expect($registration->claim_email)->toBe('dev@example.com');
});

it('generates 6-digit user code', function (): void {
    AgentRegistration::factory()->create([
        'claim_token_hash' => hash('sha256', 'clm_code'),
    ]);

    $response = $this->postJson('/agent/identity/claim', [
        'claim_token' => 'clm_code',
        'email' => 'dev@example.com',
    ]);

    $userCode = $response->json('claim_attempt.user_code');
    expect(strlen($userCode))->toBe(6)
        ->and((int) $userCode)->toBeGreaterThanOrEqual(0)
        ->and((int) $userCode)->toBeLessThanOrEqual(999999);
});

it('sets claim_code_expires_at', function (): void {
    AgentRegistration::factory()->create([
        'claim_token_hash' => hash('sha256', 'clm_expires'),
    ]);

    $this->postJson('/agent/identity/claim', [
        'claim_token' => 'clm_expires',
        'email' => 'dev@example.com',
    ]);

    $registration = AgentRegistration::where('claim_token_hash', hash('sha256', 'clm_expires'))->first();
    expect($registration->claim_code_expires_at)->not->toBeNull()
        ->and($registration->claim_code_expires_at->isFuture())->toBeTrue();
});

it('increments claim_attempts', function (): void {
    AgentRegistration::factory()->create([
        'claim_token_hash' => hash('sha256', 'clm_attempts'),
    ]);

    $this->postJson('/agent/identity/claim', [
        'claim_token' => 'clm_attempts',
        'email' => 'dev@example.com',
    ]);

    $registration = AgentRegistration::where('claim_token_hash', hash('sha256', 'clm_attempts'))->first();
    expect($registration->claim_attempts)->toBe(1);
});

it('returns verification_uri with claim_attempt_token', function (): void {
    AgentRegistration::factory()->create([
        'claim_token_hash' => hash('sha256', 'clm_uri'),
    ]);

    $response = $this->postJson('/agent/identity/claim', [
        'claim_token' => 'clm_uri',
        'email' => 'dev@example.com',
    ]);

    $uri = $response->json('claim_attempt.verification_uri');
    expect($uri)->toContain('/claim?claim_attempt_token=');
});
