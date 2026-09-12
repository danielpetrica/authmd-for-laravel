<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Enums;

enum AgentRegistrationStatus: string
{
    case Pending = 'pending';
    case Claimed = 'claimed';
    case Expired = 'expired';
    case Revoked = 'revoked';

    public function label(): string
    {
        return match ($this) {
            self::Pending => 'Pending',
            self::Claimed => 'Claimed',
            self::Expired => 'Expired',
            self::Revoked => 'Revoked',
        };
    }

    public function isActive(): bool
    {
        return $this === self::Claimed;
    }
}
