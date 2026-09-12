<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Models\AgentAccessToken;
use DanielPetrica\AuthMd\Models\AgentRegistration;

it('revokes an access token', function (): void {
    $reg = AgentRegistration::factory()->create();
    $token = AgentAccessToken::factory()->create([
        'agent_registration_id' => $reg->id,
    ]);

    $plainToken = 'at_test123';
    AgentAccessToken::where('id', $token->id)->update(['token_hash' => hash('sha256', $plainToken)]);

    $response = $this->postJson('/oauth2/revoke', ['token' => $plainToken]);

    $response->assertOk();

    $token->refresh();
    expect($token->revoked)->toBeTrue();
});

it('returns 200 for unknown token (RFC 7009)', function (): void {
    $response = $this->postJson('/oauth2/revoke', ['token' => 'at_nonexistent']);

    $response->assertOk();
});
