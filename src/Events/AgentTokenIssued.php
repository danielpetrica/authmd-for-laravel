<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Events;

use DanielPetrica\AuthMd\Models\AgentRegistration;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

final class AgentTokenIssued
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly AgentRegistration $registration,
    ) {}
}
