<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Database\Factories;

use DanielPetrica\AuthMd\Models\AgentAccessToken;
use DanielPetrica\AuthMd\Models\AgentRegistration;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/** @extends Factory<AgentAccessToken> */
final class AgentAccessTokenFactory extends Factory
{
    protected $model = AgentAccessToken::class;

    /** @return array<string, mixed> */
    public function definition(): array
    {
        return [
            'agent_registration_id' => AgentRegistration::factory(),
            'token_hash' => hash('sha256', 'at_'.Str::random(48)),
            'kid' => 'default',
            'scope' => 'api.read api.write',
            'expires_at' => now()->addDays(3),
            'revoked' => false,
            'is_pre_claim' => false,
        ];
    }

    public function preClaim(): static
    {
        return $this->state(fn (array $attributes): array => [
            'is_pre_claim' => true,
            'scope' => 'api.read',
        ]);
    }

    public function revoked(): static
    {
        return $this->state(fn (array $attributes): array => [
            'revoked' => true,
        ]);
    }
}
