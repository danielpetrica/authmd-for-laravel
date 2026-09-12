<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Services\DiscoveryService;

beforeEach(function (): void {
    $this->service = new DiscoveryService;
});

it('returns protected resource metadata', function (): void {
    $metadata = $this->service->getProtectedResourceMetadata();

    expect($metadata['resource'])->toBe('https://example.com/')
        ->and($metadata['authorization_servers'])->toBe(['https://example.com/'])
        ->and($metadata['bearer_methods_supported'])->toBe(['header']);
});

it('returns authorization server metadata', function (): void {
    $metadata = $this->service->getAuthorizationServerMetadata();

    expect($metadata['issuer'])->toBe('https://example.com')
        ->and($metadata['token_endpoint'])->toBe('https://example.com/oauth2/token')
        ->and($metadata['revocation_endpoint'])->toBe('https://example.com/oauth2/revoke')
        ->and($metadata['agent_auth'])->toHaveKeys([
            'identity_endpoint',
            'claim_endpoint',
            'identity_types_supported',
        ]);
});

it('generates auth.md markdown', function (): void {
    $md = $this->service->getAuthMarkdown();

    expect($md)->toContain('# My Application — auth.md')
        ->and($md)->toContain('Anonymous')
        ->and($md)->toContain('Service Auth');
});
