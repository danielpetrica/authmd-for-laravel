<?php

declare(strict_types=1);
use DanielPetrica\AuthMd\Events\AgentClaimed;
use DanielPetrica\AuthMd\Events\AgentRegistered;
use DanielPetrica\AuthMd\Events\AgentTokenIssued;
use DanielPetrica\AuthMd\Events\AgentTokenRevoked;

return [
    'resource' => [
        'name' => env('AGENT_AUTH_RESOURCE_NAME', 'My Application'),
        'logo_uri' => env('AGENT_AUTH_RESOURCE_LOGO', ''),
    ],

    'signing' => [
        'algorithm' => env('AGENT_AUTH_SIGNING_ALGORITHM', 'RSA256'),
        'private_key' => env('AGENT_AUTH_SIGNING_KEY'),
        'key_id' => env('AGENT_AUTH_KEY_ID', 'default'),
    ],

    'token' => [
        'ttl_hours' => (int) env('AGENT_AUTH_TOKEN_TTL_HOURS', 72),
    ],

    'registration' => [
        'ttl_hours' => (int) env('AGENT_AUTH_REGISTRATION_TTL_HOURS', 24),
        'identity_types' => ['anonymous', 'service_auth'],
    ],

    'claim' => [
        'code_ttl_minutes' => (int) env('AGENT_AUTH_CLAIM_CODE_TTL_MINUTES', 10),
        'max_attempts' => (int) env('AGENT_AUTH_CLAIM_MAX_ATTEMPTS', 5),
        'slow_down_interval' => (int) env('AGENT_AUTH_SLOW_DOWN_INTERVAL', 5),
    ],

    'scopes' => [
        'pre_claim' => ['api.read'],
        'post_claim' => ['api.read', 'api.write'],
    ],

    'rate_limits' => [
        'identity_per_ip' => 5,
        'identity_global' => 100,
        'token_per_ip' => 60,
    ],

    'cache_store' => env('AGENT_AUTH_CACHE_STORE'),

    'claim_view' => 'agent-auth::claim',

    'route_prefix' => '',

    'events' => [
        'registered' => AgentRegistered::class,
        'claimed' => AgentClaimed::class,
        'token_issued' => AgentTokenIssued::class,
        'token_revoked' => AgentTokenRevoked::class,
    ],
];
