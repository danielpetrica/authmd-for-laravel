<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Symfony\Component\HttpFoundation\Response;

final class EnsureAgentRateLimited
{
    public function handle(Request $request, Closure $next): Response
    {
        $key = 'agent-auth:identity:'.$request->ip();

        if (RateLimiter::tooManyAttempts($key, (int) config('agent-auth.rate_limits.identity_per_ip', 5))) {
            $retryAfter = RateLimiter::availableIn($key);

            return response()->json([
                'error' => 'rate_limit_exceeded',
                'error_description' => 'Too many registration attempts.',
                'retry_after' => $retryAfter,
            ], 429)->header('Retry-After', (string) $retryAfter);
        }

        RateLimiter::hit($key, 3600);

        return $next($request);
    }
}
