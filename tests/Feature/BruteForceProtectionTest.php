<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Models\AgentRegistration;

it('limits claim attempts', function (): void {
    AgentRegistration::factory()->create([
        'claim_token_hash' => hash('sha256', 'clm_brute'),
        'claim_code_expires_at' => now()->addMinutes(10),
    ]);

    for ($i = 0; $i < 5; $i++) {
        $this->postJson('/agent/identity/claim', [
            'claim_token' => 'clm_brute',
            'email' => 'dev@example.com',
        ]);
    }

    $response = $this->postJson('/agent/identity/claim', [
        'claim_token' => 'clm_brute',
        'email' => 'dev@example.com',
    ]);

    $response->assertStatus(429);
});
