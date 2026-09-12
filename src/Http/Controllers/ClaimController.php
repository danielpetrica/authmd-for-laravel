<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Http\Controllers;

use App\Models\User;
use DanielPetrica\AuthMd\Models\AgentRegistration;
use DanielPetrica\AuthMd\Services\RegistrationService;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;

final class ClaimController extends Controller
{
    public function __construct(
        private readonly RegistrationService $registrations,
    ) {}

    public function show(Request $request): View|RedirectResponse
    {
        $attemptToken = $request->query('claim_attempt_token');

        if (! $attemptToken) {
            abort(404);
        }

        // If not authenticated, redirect to GitHub OAuth with return URL
        if (! auth()->check()) {
            $returnUrl = route('agent-auth.claim.show', ['claim_attempt_token' => $attemptToken]);

            return redirect()->route('oauth.github.redirect', ['panel' => 'artisan_panel'])
                ->with('url.intended', $returnUrl);
        }

        $hashedToken = hash('sha256', (string) $attemptToken);
        $registration = AgentRegistration::where('claim_attempt_token_hash', $hashedToken)->first();

        if (! $registration || ($registration->claim_code_expires_at?->isPast() ?? true)) {
            abort(410, 'Claim code expired.');
        }

        return view((string) config('agent-auth.claim_view', 'agent-auth::claim'), [
            'registration' => $registration,
            'claim_attempt_token' => $attemptToken,
        ]);
    }

    public function complete(Request $request): RedirectResponse
    {
        $validated = $request->validate([
            'claim_attempt_token' => 'required|string',
            'user_code' => 'required|string|size:6',
        ]);

        $hashedAttemptToken = hash('sha256', $validated['claim_attempt_token']);
        $registration = AgentRegistration::where('claim_attempt_token_hash', $hashedAttemptToken)->first();

        if (! $registration || ($registration->claim_code_expires_at?->isPast() ?? true)) {
            return back()->withErrors(['user_code' => 'Claim code expired.']);
        }

        $validCode = hash_equals(
            (string) $registration->claim_user_code_hash,
            hash('sha256', $validated['user_code'])
        );

        if (! $validCode) {
            return back()->withErrors(['user_code' => 'Invalid code.']);
        }

        /** @var User|null $user */
        $user = auth()->user();

        // Verify the signed-in user matches claim_email
        if ($registration->claim_email && $user?->email !== $registration->claim_email) {
            abort(403, 'This claim is for a different email address.');
        }

        // Link user to registration if not already linked
        if (! $registration->user_id && $user) {
            $registration->update(['user_id' => $user->id]);
        }

        // Mark claimed
        $this->registrations->markClaimed(
            registration: $registration,
            userId: (int) ($user?->id ?? 0),
        );

        // Auto-login and redirect to artisan panel
        if ($user) {
            Auth::login($user, remember: true);
        }

        return redirect('/artisan_panel')
            ->with('status', 'Agent registration claimed successfully.');
    }

    public function success(): View
    {
        return view('agent-auth::claim-success');
    }
}
