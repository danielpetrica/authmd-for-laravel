<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Claim Agent Registration</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen flex items-center justify-center">
    <div class="max-w-md w-full bg-white shadow rounded-lg p-8">
        <h1 class="text-xl font-semibold text-gray-900 mb-4">Claim Agent Registration</h1>

        @if ($errors->any())
            <div class="bg-red-50 border border-red-200 rounded p-4 mb-4">
                @foreach ($errors->all() as $error)
                    <p class="text-red-600 text-sm">{{ $error }}</p>
                @endforeach
            </div>
        @endif

        <p class="text-gray-600 mb-6">Enter the 6-digit code shown by your agent to complete registration.</p>

        <form method="POST" action="{{ route('agent-auth.claim.complete') }}">
            @csrf
            <input type="hidden" name="claim_attempt_token" value="{{ $claim_attempt_token }}">

            <div class="mb-4">
                <label for="user_code" class="block text-sm font-medium text-gray-700 mb-1">Verification Code</label>
                <input type="text"
                       id="user_code"
                       name="user_code"
                       maxlength="6"
                       pattern="[0-9]{6}"
                       autocomplete="off"
                       class="block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 text-center text-2xl tracking-widest font-mono"
                       required
                       autofocus>
            </div>

            <button type="submit"
                    class="w-full bg-indigo-600 text-white py-2 px-4 rounded hover:bg-indigo-700 transition">
                Claim Registration
            </button>
        </form>
    </div>
</body>
</html>
