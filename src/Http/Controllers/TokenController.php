<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Http\Controllers;

use DanielPetrica\AuthMd\Services\TokenService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Cache;

final class TokenController extends Controller
{
    public function __construct(
        private readonly TokenService $tokens,
    ) {}

    public function token(Request $request): JsonResponse
    {
        $grantType = $request->input('grant_type');

        return match ($grantType) {
            'urn:ietf:params:oauth:grant-type:jwt-bearer' => $this->handleJwtBearerGrant($request),
            'urn:workos:agent-auth:grant-type:claim' => $this->handleClaimGrant($request),
            default => response()->json([
                'error' => 'unsupported_grant_type',
                'error_description' => 'Unsupported grant type.',
            ], 400),
        };
    }

    private function handleJwtBearerGrant(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'assertion' => 'required|string',
        ]);

        $result = $this->tokens->exchangeAssertion($validated['assertion']);

        return response()->json($result);
    }

    private function handleClaimGrant(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'claim_token' => 'required|string',
        ]);

        $cacheStore = (string) config('agent-auth.cache_store', cache()->getDefaultDriver());
        $pollKey = 'agent_auth:poll:'.hash('sha256', $validated['claim_token']);
        $lastPoll = Cache::store($cacheStore)->get($pollKey);

        if ($lastPoll instanceof \DateTimeInterface) {
            $elapsed = now()->diffInSeconds($lastPoll);
            $interval = (int) config('agent-auth.claim.slow_down_interval', 5);

            if ($elapsed < $interval) {
                return response()->json([
                    'error' => 'slow_down',
                    'error_description' => 'Poll too fast.',
                ], 400);
            }
        }

        Cache::store($cacheStore)->put($pollKey, now(), now()->addMinutes(15));

        $result = $this->tokens->handleClaimGrant($validated['claim_token']);

        return response()->json($result);
    }

    public function revoke(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'token' => 'required|string',
        ]);

        $this->tokens->revoke($validated['token']);

        return response()->json([], 200);
    }
}
