<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Models;

use DanielPetrica\AuthMd\Enums\AgentRegistrationStatus;
use DanielPetrica\AuthMd\Enums\IdentityType;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

/**
 * @property int $id
 * @property string $registration_id
 * @property string $type
 * @property string $status
 * @property string|null $claim_token_hash
 * @property string|null $claim_email
 * @property string|null $claim_attempt_token_hash
 * @property string|null $claim_user_code_hash
 * @property Carbon|null $claim_code_expires_at
 * @property int $claim_attempts
 * @property int|null $user_id
 * @property Carbon $expires_at
 * @property Carbon|null $claimed_at
 * @property string|null $ip
 * @property array<string, mixed>|null $metadata
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AgentRegistration extends Model
{
    use HasFactory;

    /** @var string */
    protected $table = 'agent_registrations';

    /** @var array<int, string> */
    protected $guarded = [];

    /** @var array<string, string> */
    protected $casts = [
        'expires_at' => 'datetime',
        'claimed_at' => 'datetime',
        'claim_code_expires_at' => 'datetime',
        'metadata' => 'array',
        'claim_attempts' => 'int',
    ];

    /** @var array<int, string> */
    protected $hidden = [
        'claim_token_hash',
        'claim_attempt_token_hash',
        'claim_user_code_hash',
    ];

    public function accessTokens(): HasMany
    {
        return $this->hasMany(AgentAccessToken::class);
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(config('auth.providers.users.model', 'App\\Models\\User'));
    }

    public function statusEnum(): AgentRegistrationStatus
    {
        return AgentRegistrationStatus::from($this->status);
    }

    public function typeEnum(): IdentityType
    {
        return IdentityType::from($this->type);
    }

    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }

    public function isClaimed(): bool
    {
        return $this->status === AgentRegistrationStatus::Claimed->value;
    }

    public static function generateRegistrationId(): string
    {
        return 'reg_'.Str::random(26);
    }
}
