<?php

declare(strict_types=1);

use DanielPetrica\AuthMd\Enums\AgentRegistrationStatus;
use DanielPetrica\AuthMd\Enums\IdentityType;

it('returns correct labels for AgentRegistrationStatus', function (): void {
    expect(AgentRegistrationStatus::Pending->label())->toBe('Pending')
        ->and(AgentRegistrationStatus::Claimed->label())->toBe('Claimed')
        ->and(AgentRegistrationStatus::Expired->label())->toBe('Expired')
        ->and(AgentRegistrationStatus::Revoked->label())->toBe('Revoked');
});

it('identifies active status correctly', function (): void {
    expect(AgentRegistrationStatus::Claimed->isActive())->toBeTrue()
        ->and(AgentRegistrationStatus::Pending->isActive())->toBeFalse()
        ->and(AgentRegistrationStatus::Expired->isActive())->toBeFalse()
        ->and(AgentRegistrationStatus::Revoked->isActive())->toBeFalse();
});

it('returns correct labels for IdentityType', function (): void {
    expect(IdentityType::Anonymous->label())->toBe('Anonymous')
        ->and(IdentityType::ServiceAuth->label())->toBe('Service Auth');
});
