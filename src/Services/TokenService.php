<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Services;

use DanielPetrica\AuthMd\Enums\AgentRegistrationStatus;
use DanielPetrica\AuthMd\Enums\IdentityType;
use DanielPetrica\AuthMd\Events\AgentTokenIssued;
use DanielPetrica\AuthMd\Events\AgentTokenRevoked;
use DanielPetrica\AuthMd\Models\AgentAccessToken;
use DanielPetrica\AuthMd\Models\AgentRegistration;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\Cache;

final class TokenService
{
    public function __construct(
        private readonly JwtSigningService $jwt,
    ) {}

    public static function make(): self
    {
        return new self(jwt: JwtSigningService::make());
    }

    public function issue(AgentRegistration $registration, bool $isPreClaim = false): string
    {
        $plainToken = AgentAccessToken::generateToken();
        $scopes = $isPreClaim
            ? (array) config('agent-auth.scopes.pre_claim', ['api.read'])
            : (array) config('agent-auth.scopes.post_claim', ['api.read', 'api.write']);

        AgentAccessToken::create([
            'agent_registration_id' => $registration->id,
            'token_hash' => AgentAccessToken::hashToken($plainToken),
            'kid' => (string) config('agent-auth.signing.key_id', 'default'),
            'scope' => implode(' ', $scopes),
            'expires_at' => now()->addHours((int) config('agent-auth.token.ttl_hours', 72)),
            'is_pre_claim' => $isPreClaim,
        ]);

        event(new AgentTokenIssued($registration));

        return $plainToken;
    }

    /** @return array{access_token: string, token_type: string, expires_in: int, scope: string} */
    public function exchangeAssertion(string $assertion): array
    {
        $claims = $this->jwt->verify($assertion);

        $registration = AgentRegistration::where('registration_id', $claims->sub)->first();

        if (! $registration || $registration->isExpired()) {
            throw new HttpResponseException(
                response()->json(['error' => 'invalid_grant', 'error_description' => 'Invalid or expired assertion.'], 400)
            );
        }

        // Assertions are bearer credentials: burn them on first use so a leaked
        // or replayed assertion cannot mint additional access tokens.
        $assertionKey = 'agent-auth:assertion:'.hash('sha256', $assertion);

        if (! Cache::store(config('agent-auth.cache_store') ?: null)->add(
            key: $assertionKey,
            value: true,
            ttl: now()->addHours((int) config('agent-auth.registration.ttl_hours', 24)),
        )) {
            throw new HttpResponseException(
                response()->json(['error' => 'invalid_grant', 'error_description' => 'Assertion has already been used.'], 400)
            );
        }

        $isPreClaim = $registration->status === AgentRegistrationStatus::Pending->value
            && $registration->type === IdentityType::Anonymous->value;

        $token = $this->issue($registration, isPreClaim: $isPreClaim);

        $scopes = $isPreClaim
            ? (array) config('agent-auth.scopes.pre_claim')
            : (array) config('agent-auth.scopes.post_claim');

        return [
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => (int) config('agent-auth.token.ttl_hours', 72) * 3600,
            'scope' => implode(' ', $scopes),
        ];
    }

    /** @return array{access_token: string, token_type: string, expires_in: int, scope: string, identity_assertion: string, assertion_expires: string} */
    public function handleClaimGrant(string $plainClaimToken): array
    {
        $registration = app(RegistrationService::class)->findByClaimToken($plainClaimToken);

        if (! $registration || $registration->isExpired()) {
            throw new HttpResponseException(
                response()->json(['error' => 'expired_token', 'error_description' => 'Claim window closed.'], 400)
            );
        }

        if (! $registration->isClaimed()) {
            throw new HttpResponseException(
                response()->json(['error' => 'authorization_pending', 'error_description' => 'User has not completed the ceremony.'], 400)
            );
        }

        $registration->accessTokens()
            ->where('is_pre_claim', true)
            ->update(['revoked' => true]);

        $token = $this->issue($registration, isPreClaim: false);

        $assertion = $this->jwt->sign([
            'sub' => $registration->registration_id,
            'email' => $registration->claim_email,
            'email_verified' => true,
        ]);

        return [
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => (int) config('agent-auth.token.ttl_hours', 72) * 3600,
            'scope' => implode(' ', (array) config('agent-auth.scopes.post_claim')),
            'identity_assertion' => $assertion,
            'assertion_expires' => now()->addHours((int) config('agent-auth.token.ttl_hours', 72))->toIso8601String(),
        ];
    }

    public function revoke(string $plainToken): void
    {
        $hashed = AgentAccessToken::hashToken($plainToken);

        AgentAccessToken::where('token_hash', $hashed)->update(['revoked' => true]);

        event(new AgentTokenRevoked);
    }

    public function validate(string $plainToken): ?AgentRegistration
    {
        $hashed = AgentAccessToken::hashToken($plainToken);

        $token = AgentAccessToken::where('token_hash', $hashed)
            ->where('revoked', false)
            ->where('expires_at', '>', now())
            ->first();

        if (! $token) {
            return null;
        }

        $token->update(['last_used_at' => now()]);

        return $token->registration;
    }
}
