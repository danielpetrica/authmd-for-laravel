<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('agent_access_tokens', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('agent_registration_id')->constrained()->cascadeOnDelete();
            $table->string('token_hash')->unique();
            $table->string('kid');
            $table->string('scope');
            $table->timestamp('expires_at');
            $table->boolean('revoked')->default(false);
            $table->boolean('is_pre_claim')->default(false);
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();

            $table->index(['agent_registration_id', 'revoked']);
            $table->index('token_hash');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('agent_access_tokens');
    }
};
