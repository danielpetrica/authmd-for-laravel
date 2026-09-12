<?php

declare(strict_types=1);

it('serves protected resource metadata', function (): void {
    $response = $this->getJson('/.well-known/oauth-protected-resource');

    $response->assertOk()
        ->assertJsonPath('resource', 'https://example.com/')
        ->assertJsonPath('bearer_methods_supported', ['header']);
});

it('serves authorization server metadata', function (): void {
    $response = $this->getJson('/.well-known/oauth-authorization-server');

    $response->assertOk()
        ->assertJsonPath('issuer', 'https://example.com')
        ->assertJsonPath('agent_auth.identity_endpoint', 'https://example.com/agent/identity');
});

it('serves jwks', function (): void {
    $response = $this->getJson('/.well-known/jwks.json');

    $response->assertOk()
        ->assertJsonStructure(['keys']);
});

it('serves auth.md', function (): void {
    $response = $this->get('/auth.md');

    $response->assertOk()
        ->assertHeader('Content-Type', 'text/plain; charset=UTF-8')
        ->assertSee('auth.md');
});
