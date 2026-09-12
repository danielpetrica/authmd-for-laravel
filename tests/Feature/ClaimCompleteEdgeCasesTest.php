<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Models\AgentRegistration;
use Tests\Models\User;

beforeEach(function (): void {
    $this->user = User::factory()->create(['email' => 'dev@example.com']);
});

it('rejects claim with expired code', function (): void {
    $this->actingAs($this->user);

    AgentRegistration::factory()->create([
        'claim_email' => 'dev@example.com',
        'claim_attempt_token_hash' => hash('sha256', 'cla_expired'),
        'claim_user_code_hash' => hash('sha256', '123456'),
        'claim_code_expires_at' => now()->subMinutes(5),
    ]);

    $response = $this->post('/claim/complete', [
        'claim_attempt_token' => 'cla_expired',
        'user_code' => '123456',
    ]);

    $response->assertSessionHasErrors('user_code');
});

it('rejects claim from wrong email', function (): void {
    $wrongUser = User::factory()->create(['email' => 'wrong@example.com']);
    $this->actingAs($wrongUser);

    AgentRegistration::factory()->create([
        'claim_email' => 'dev@example.com',
        'claim_attempt_token_hash' => hash('sha256', 'cla_wrong'),
        'claim_user_code_hash' => hash('sha256', '123456'),
        'claim_code_expires_at' => now()->addMinutes(10),
    ]);

    $response = $this->post('/claim/complete', [
        'claim_attempt_token' => 'cla_wrong',
        'user_code' => '123456',
    ]);

    $response->assertStatus(403);
});

it('claim page returns 404 without token', function (): void {
    $this->actingAs($this->user);

    $this->get('/claim')->assertNotFound();
});

it('claim page returns 410 for expired code', function (): void {
    $this->actingAs($this->user);

    AgentRegistration::factory()->create([
        'claim_attempt_token_hash' => hash('sha256', 'cla_show_expired'),
        'claim_code_expires_at' => now()->subMinutes(5),
    ]);

    $this->get('/claim?claim_attempt_token=cla_show_expired')->assertStatus(410);
});
