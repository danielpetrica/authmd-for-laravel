<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Models\AgentAccessToken;
use DanielPetrica\AuthMd\Models\AgentRegistration;

it('generates a valid registration ID', function (): void {
    $id = AgentRegistration::generateRegistrationId();

    expect($id)->toStartWith('reg_')
        ->and(strlen($id))->toBeGreaterThan(4);
});

it('generates a valid token', function (): void {
    $token = AgentAccessToken::generateToken();

    expect($token)->toStartWith('at_')
        ->and(strlen($token))->toBeGreaterThan(4);
});

it('hashes tokens consistently', function (): void {
    $token = 'at_test123';
    $hash1 = AgentAccessToken::hashToken($token);
    $hash2 = AgentAccessToken::hashToken($token);

    expect($hash1)->toBe($hash2)
        ->and(strlen($hash1))->toBe(64); // SHA-256 hex
});

it('marks registration as expired correctly', function (): void {
    $registration = AgentRegistration::factory()->create([
        'expires_at' => now()->subHour(),
    ]);

    expect($registration->isExpired())->toBeTrue();
});

it('marks registration as not expired when future', function (): void {
    $registration = AgentRegistration::factory()->create([
        'expires_at' => now()->addDay(),
    ]);

    expect($registration->isExpired())->toBeFalse();
});

it('identifies claimed registration', function (): void {
    $registration = AgentRegistration::factory()->claimed()->create();

    expect($registration->isClaimed())->toBeTrue();
});

it('identifies unclaimed registration', function (): void {
    $registration = AgentRegistration::factory()->create();

    expect($registration->isClaimed())->toBeFalse();
});

it('validates access token correctly', function (): void {
    $token = AgentAccessToken::factory()->create([
        'expires_at' => now()->addDay(),
        'revoked' => false,
    ]);

    expect($token->isValid())->toBeTrue();
});

it('invalidates expired access token', function (): void {
    $token = AgentAccessToken::factory()->create([
        'expires_at' => now()->subHour(),
        'revoked' => false,
    ]);

    expect($token->isValid())->toBeFalse();
});

it('invalidates revoked access token', function (): void {
    $token = AgentAccessToken::factory()->revoked()->create([
        'expires_at' => now()->addDay(),
    ]);

    expect($token->isValid())->toBeFalse();
});

it('hides sensitive attributes from serialization', function (): void {
    $registration = AgentRegistration::factory()->create();
    $array = $registration->toArray();

    expect($array)->not->toHaveKey('claim_token_hash')
        ->and($array)->not->toHaveKey('claim_attempt_token_hash')
        ->and($array)->not->toHaveKey('claim_user_code_hash');

    $token = AgentAccessToken::factory()->create();
    $tokenArray = $token->toArray();

    expect($tokenArray)->not->toHaveKey('token_hash');
});
