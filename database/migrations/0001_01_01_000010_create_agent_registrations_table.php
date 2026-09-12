<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('agent_registrations', function (Blueprint $table): void {
            $table->id();
            $table->string('registration_id')->unique();
            $table->string('type');
            $table->string('status')->default('pending');
            $table->string('claim_token_hash')->nullable()->unique();
            $table->string('claim_email')->nullable();
            $table->string('claim_attempt_token_hash')->nullable();
            $table->string('claim_user_code_hash')->nullable();
            $table->timestamp('claim_code_expires_at')->nullable();
            $table->integer('claim_attempts')->default(0);
            $table->foreignId('user_id')->nullable()->constrained()->nullOnDelete();
            $table->timestamp('expires_at');
            $table->timestamp('claimed_at')->nullable();
            $table->string('ip')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['status', 'expires_at']);
            $table->index('claim_email');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('agent_registrations');
    }
};
