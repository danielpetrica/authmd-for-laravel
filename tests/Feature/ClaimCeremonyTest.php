<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Enums\AgentRegistrationStatus;
use DanielPetrica\AuthMd\Models\AgentRegistration;
use Tests\Models\User;

beforeEach(function (): void {
    $this->user = User::factory()->create(['email' => 'dev@example.com']);
});

it('starts claim ceremony', function (): void {
    AgentRegistration::factory()->create([
        'claim_token_hash' => hash('sha256', 'clm_test123'),
    ]);

    $response = $this->postJson('/agent/identity/claim', [
        'claim_token' => 'clm_test123',
        'email' => 'dev@example.com',
    ]);

    $response->assertOk()
        ->assertJsonStructure([
            'registration_id',
            'claim_attempt',
        ])
        ->assertJsonPath('claim_attempt.user_code', fn (string $code) => strlen($code) === 6)
        ->assertJsonPath('claim_attempt.interval', 5);
});

it('completes claim ceremony', function (): void {
    $this->actingAs($this->user);

    $reg = AgentRegistration::factory()->create([
        'claim_email' => 'dev@example.com',
        'claim_attempt_token_hash' => hash('sha256', 'cla_valid'),
        'claim_user_code_hash' => hash('sha256', '123456'),
        'claim_code_expires_at' => now()->addMinutes(10),
    ]);

    $response = $this->post('/claim/complete', [
        'claim_attempt_token' => 'cla_valid',
        'user_code' => '123456',
    ]);

    $response->assertRedirect();

    $reg->refresh();
    expect($reg->status)->toBe(AgentRegistrationStatus::Claimed->value)
        ->and($reg->user_id)->toBe($this->user->id);
});

it('rejects invalid user code', function (): void {
    $this->actingAs($this->user);

    AgentRegistration::factory()->create([
        'claim_email' => 'dev@example.com',
        'claim_attempt_token_hash' => hash('sha256', 'cla_valid'),
        'claim_user_code_hash' => hash('sha256', '123456'),
        'claim_code_expires_at' => now()->addMinutes(10),
    ]);

    $response = $this->post('/claim/complete', [
        'claim_attempt_token' => 'cla_valid',
        'user_code' => '999999',
    ]);

    $response->assertSessionHasErrors('user_code');
});
