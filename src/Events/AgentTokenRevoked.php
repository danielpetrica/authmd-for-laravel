<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

final class AgentTokenRevoked
{
    use Dispatchable, SerializesModels;

    public function __construct() {}
}
