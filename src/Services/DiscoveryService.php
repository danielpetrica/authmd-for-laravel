<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Services;

final class DiscoveryService
{
    /** @return array<string, mixed> */
    public function getProtectedResourceMetadata(): array
    {
        $url = config('app.url');

        return [
            'resource' => $url.'/',
            'resource_name' => config('agent-auth.resource.name', 'My Application'),
            'resource_logo_uri' => config('agent-auth.resource.logo_uri', ''),
            'authorization_servers' => [$url.'/'],
            'scopes_supported' => array_values(array_unique(array_merge(
                (array) config('agent-auth.scopes.pre_claim', []),
                (array) config('agent-auth.scopes.post_claim', []),
            ))),
            'bearer_methods_supported' => ['header'],
        ];
    }

    /** @return array<string, mixed> */
    public function getAuthorizationServerMetadata(): array
    {
        $url = config('app.url');

        return [
            'resource' => $url.'/',
            'authorization_servers' => [$url.'/'],
            'scopes_supported' => array_values(array_unique(array_merge(
                (array) config('agent-auth.scopes.pre_claim', []),
                (array) config('agent-auth.scopes.post_claim', []),
            ))),
            'bearer_methods_supported' => ['header'],

            'issuer' => $url,
            'token_endpoint' => $url.'/oauth2/token',
            'revocation_endpoint' => $url.'/oauth2/revoke',
            'grant_types_supported' => [
                'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'urn:workos:agent-auth:grant-type:claim',
            ],

            'agent_auth' => [
                'skill' => $url.'/auth.md',
                'identity_endpoint' => $url.'/agent/identity',
                'claim_endpoint' => $url.'/agent/identity/claim',
                'events_endpoint' => $url.'/agent/event/notify',
                'identity_types_supported' => (array) config('agent-auth.registration.identity_types', ['anonymous', 'service_auth']),
                'events_supported' => [],
            ],
        ];
    }

    public function getAuthMarkdown(): string
    {
        $name = config('agent-auth.resource.name', 'My Application');
        $url = config('app.url');

        return <<<MD
        # {$name} — auth.md

        ## Authentication

        This service supports agent-initiated user registration via the [auth.md protocol](https://workos.com/auth-md).

        ### Supported Flows

        - **Anonymous**: Register without a user identity. Claim later via code ceremony.
        - **Service Auth**: Register with a user email. Claim immediately via code ceremony.

        ### Discovery

        1. Fetch `{$url}/.well-known/oauth-protected-resource`
        2. Fetch `{$url}/.well-known/oauth-authorization-server`
        3. Use `agent_auth.identity_endpoint` to register

        ### Scopes

        - `api.read` — Pre-claim scope
        - `api.read api.write` — Post-claim scope

        ### Endpoints

        - **Register**: `POST {$url}/agent/identity`
        - **Claim**: `POST {$url}/agent/identity/claim`
        - **Token**: `POST {$url}/oauth2/token`
        - **Revoke**: `POST {$url}/oauth2/revoke`
        MD;
    }
}
