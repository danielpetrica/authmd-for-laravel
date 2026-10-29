<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Http\Controllers;

use DanielPetrica\AuthMd\Services\JwtSigningService;
use DanielPetrica\AuthMd\Services\RegistrationService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

final class AgentIdentityController extends Controller
{
    public function __construct(
        private readonly RegistrationService $registrations,
        private readonly JwtSigningService $jwt,
    ) {}

    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'type' => 'required|in:anonymous,service_auth',
            'login_hint' => 'required_if:type,service_auth|nullable|email',
        ]);

        $claimToken = 'clm_'.Str::random(25);

        $registration = match ($validated['type']) {
            'anonymous' => $this->registrations->createAnonymous(
                ip: (string) $request->ip(),
                claimToken: $claimToken,
            ),
            'service_auth' => $this->registrations->createServiceAuth(
                email: (string) $validated['login_hint'],
                ip: (string) $request->ip(),
                claimToken: $claimToken,
            ),
            default => abort(422, json_encode(['error' => 'invalid_type'])),
        };

        $assertion = $this->jwt->sign(['sub' => $registration->registration_id]);

        $response = [
            'registration_id' => $registration->registration_id,
            'registration_type' => $validated['type'],
            'identity_assertion' => $assertion,
            'assertion_expires' => $registration->expires_at->toIso8601String(),
            'claim_url' => '/agent/identity/claim',
            'claim_token' => $claimToken,
            'claim_token_expires' => $registration->expires_at->toIso8601String(),
            'post_claim_scopes' => config('agent-auth.scopes.post_claim'),
        ];

        if ($validated['type'] === 'anonymous') {
            $response['pre_claim_scopes'] = config('agent-auth.scopes.pre_claim');
        }

        return response()->json($response);
    }

    public function claim(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'claim_token' => 'required|string',
            'email' => 'required|email',
        ]);

        $registration = $this->registrations->findByClaimToken($validated['claim_token']);

        if (! $registration) {
            return response()->json(['error' => 'invalid_claim_token'], 400);
        }

        if ($registration->isClaimed()) {
            return response()->json(['error' => 'claimed_or_in_flight'], 400);
        }

        if ($registration->isExpired()) {
            return response()->json(['error' => 'claim_expired'], 400);
        }

        $cache = Cache::store(config('agent-auth.cache_store') ?: null);
        $attemptKey = "agent_auth:claim_attempts:{$registration->id}";
        $attempts = (int) $cache->get($attemptKey, 0);

        if ($attempts >= (int) config('agent-auth.claim.max_attempts', 5)) {
            return response()->json(['error' => 'too_many_attempts'], 429);
        }

        $userCode = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $claimAttemptToken = 'cla_'.Str::random(25);

        $registration->update([
            'claim_email' => $validated['email'],
            'claim_attempt_token_hash' => hash('sha256', $claimAttemptToken),
            'claim_user_code_hash' => hash('sha256', $userCode),
            'claim_code_expires_at' => now()->addMinutes((int) config('agent-auth.claim.code_ttl_minutes', 10)),
            'claim_attempts' => $attempts + 1,
        ]);

        $cache->put($attemptKey, $attempts + 1, now()->addMinutes(15));

        return response()->json([
            'registration_id' => $registration->registration_id,
            'claim_attempt_id' => $claimAttemptToken,
            'status' => 'initiated',
            'expires_at' => $registration->claim_code_expires_at->toIso8601String(),
            'claim_attempt' => [
                'user_code' => $userCode,
                'expires_in' => (int) config('agent-auth.claim.code_ttl_minutes', 10) * 60,
                'verification_uri' => config('app.url').'/claim?claim_attempt_token='.$claimAttemptToken,
                'interval' => (int) config('agent-auth.claim.slow_down_interval', 5),
            ],
        ]);
    }
}
