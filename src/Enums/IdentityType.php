<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Enums;

enum IdentityType: string
{
    case Anonymous = 'anonymous';
    case ServiceAuth = 'service_auth';

    public function label(): string
    {
        return match ($this) {
            self::Anonymous => 'Anonymous',
            self::ServiceAuth => 'Service Auth',
        };
    }
}
