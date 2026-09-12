<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Services\JwtSigningService;

beforeEach(function (): void {
    $this->service = JwtSigningService::make();
});

it('signs and verifies a jwt', function (): void {
    $token = $this->service->sign(['sub' => 'reg_123']);
    $claims = $this->service->verify($token);

    expect($claims->sub)->toBe('reg_123')
        ->and($claims->iss)->toBe('https://example.com')
        ->and($claims->aud)->toBe('https://example.com');
});

it('returns valid jwks', function (): void {
    $jwks = $this->service->getJwks();

    expect($jwks)->toHaveKeys(['keys'])
        ->and($jwks['keys'])->toHaveCount(1)
        ->and($jwks['keys'][0])->toHaveKeys(['kid', 'kty', 'alg', 'use']);
});
