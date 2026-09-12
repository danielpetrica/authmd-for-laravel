<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Database\Factories;

use DanielPetrica\AuthMd\Enums\AgentRegistrationStatus;
use DanielPetrica\AuthMd\Enums\IdentityType;
use DanielPetrica\AuthMd\Models\AgentRegistration;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/** @extends Factory<AgentRegistration> */
final class AgentRegistrationFactory extends Factory
{
    protected $model = AgentRegistration::class;

    /** @return array<string, mixed> */
    public function definition(): array
    {
        return [
            'registration_id' => 'reg_'.Str::random(26),
            'type' => IdentityType::Anonymous->value,
            'status' => AgentRegistrationStatus::Pending->value,
            'claim_token_hash' => hash('sha256', 'clm_'.Str::random(25)),
            'expires_at' => now()->addDay(),
            'ip' => fake()->ipv4(),
        ];
    }

    public function claimed(): static
    {
        return $this->state(fn (array $attributes): array => [
            'status' => AgentRegistrationStatus::Claimed->value,
            'claimed_at' => now(),
            'user_id' => 1,
        ]);
    }

    public function expired(): static
    {
        return $this->state(fn (array $attributes): array => [
            'status' => AgentRegistrationStatus::Expired->value,
            'expires_at' => now()->subHour(),
        ]);
    }
}
