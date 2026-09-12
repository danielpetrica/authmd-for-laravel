<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

/**
 * @property int $id
 * @property int $agent_registration_id
 * @property string $token_hash
 * @property string $kid
 * @property string $scope
 * @property Carbon $expires_at
 * @property bool $revoked
 * @property bool $is_pre_claim
 * @property Carbon|null $last_used_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
final class AgentAccessToken extends Model
{
    use HasFactory;

    /** @var string */
    protected $table = 'agent_access_tokens';

    /** @var array<int, string> */
    protected $guarded = [];

    /** @var array<string, string> */
    protected $casts = [
        'expires_at' => 'datetime',
        'last_used_at' => 'datetime',
        'revoked' => 'boolean',
        'is_pre_claim' => 'boolean',
    ];

    /** @var array<int, string> */
    protected $hidden = ['token_hash'];

    public function registration(): BelongsTo
    {
        return $this->belongsTo(AgentRegistration::class, 'agent_registration_id');
    }

    public function isValid(): bool
    {
        return ! $this->revoked && $this->expires_at->isFuture();
    }

    public static function generateToken(): string
    {
        return 'at_'.Str::random(48);
    }

    public static function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }
}
