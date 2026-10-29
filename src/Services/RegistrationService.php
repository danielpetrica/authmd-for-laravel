<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Services;

use DanielPetrica\AuthMd\Enums\AgentRegistrationStatus;
use DanielPetrica\AuthMd\Enums\IdentityType;
use DanielPetrica\AuthMd\Events\AgentClaimed;
use DanielPetrica\AuthMd\Events\AgentRegistered;
use DanielPetrica\AuthMd\Models\AgentRegistration;

final class RegistrationService
{
    public function createAnonymous(string $ip, string $claimToken, ?array $metadata = null): AgentRegistration
    {
        $registration = AgentRegistration::create([
            'registration_id' => AgentRegistration::generateRegistrationId(),
            'type' => IdentityType::Anonymous->value,
            'status' => AgentRegistrationStatus::Pending->value,
            'claim_token_hash' => hash('sha256', $claimToken),
            'expires_at' => now()->addHours((int) config('agent-auth.registration.ttl_hours', 24)),
            'ip' => $ip,
            'metadata' => $metadata,
        ]);

        event(new AgentRegistered($registration));

        return $registration;
    }

    public function createServiceAuth(string $email, string $ip, string $claimToken, ?array $metadata = null): AgentRegistration
    {
        $registration = AgentRegistration::create([
            'registration_id' => AgentRegistration::generateRegistrationId(),
            'type' => IdentityType::ServiceAuth->value,
            'status' => AgentRegistrationStatus::Pending->value,
            'claim_token_hash' => hash('sha256', $claimToken),
            'claim_email' => $email,
            'expires_at' => now()->addHours((int) config('agent-auth.registration.ttl_hours', 24)),
            'ip' => $ip,
            'metadata' => $metadata,
        ]);

        event(new AgentRegistered($registration));

        return $registration;
    }

    public function findByClaimToken(string $plainToken): ?AgentRegistration
    {
        return AgentRegistration::where('claim_token_hash', hash('sha256', $plainToken))->first();
    }

    public function markClaimed(AgentRegistration $registration, int $userId): void
    {
        $registration->update([
            'status' => AgentRegistrationStatus::Claimed->value,
            'user_id' => $userId,
            'claimed_at' => now(),
        ]);

        $registration->accessTokens()
            ->where('is_pre_claim', true)
            ->update(['revoked' => true]);

        event(new AgentClaimed($registration));
    }

    public function markExpired(AgentRegistration $registration): void
    {
        $registration->update(['status' => AgentRegistrationStatus::Expired->value]);
    }

    public function expireUnclaimed(): int
    {
        return (int) AgentRegistration::query()
            ->where('status', AgentRegistrationStatus::Pending->value)
            ->where('expires_at', '<', now())
            ->update(['status' => AgentRegistrationStatus::Expired->value]);
    }
}
