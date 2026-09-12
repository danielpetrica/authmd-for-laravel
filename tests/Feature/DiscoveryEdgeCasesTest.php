<?php

declare(strict_types=1);

it('prm includes resource_name from config', function (): void {
    $response = $this->getJson('/.well-known/oauth-protected-resource');

    expect($response->json('resource_name'))->toBe('My Application');
});

it('as metadata includes grant types', function (): void {
    $response = $this->getJson('/.well-known/oauth-authorization-server');

    expect($response->json('grant_types_supported'))->toContain('urn:ietf:params:oauth:grant-type:jwt-bearer')
        ->and($response->json('grant_types_supported'))->toContain('urn:workos:agent-auth:grant-type:claim');
});

it('as metadata includes identity_types_supported', function (): void {
    $response = $this->getJson('/.well-known/oauth-authorization-server');

    expect($response->json('agent_auth.identity_types_supported'))->toContain('anonymous')
        ->and($response->json('agent_auth.identity_types_supported'))->toContain('service_auth');
});

it('jwks returns RSA key type', function (): void {
    $response = $this->getJson('/.well-known/jwks.json');

    expect($response->json('keys.0.kty'))->toBe('RSA')
        ->and($response->json('keys.0.alg'))->toBe('RS256')
        ->and($response->json('keys.0.use'))->toBe('sig');
});

it('auth.md contains supported flows', function (): void {
    $response = $this->get('/auth.md');

    $response->assertOk()
        ->assertSee('Anonymous')
        ->assertSee('Service Auth')
        ->assertSee('agent/identity');
});
