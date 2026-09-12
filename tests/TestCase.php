<?php

declare(strict_types=1);

namespace Tests;

use DanielPetrica\AuthMd\AuthMdServiceProvider;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpDatabase();

        Factory::guessFactoryNamesUsing(function (string $modelName): string {
            $classBasename = class_basename($modelName);

            if ($classBasename === 'User') {
                return 'Tests\\Models\\UserFactory';
            }

            return "DanielPetrica\\AuthMd\\Database\\Factories\\{$classBasename}Factory";
        });
    }

    protected function getPackageProviders($app): array
    {
        return [AuthMdServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.url', 'https://example.com');
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('agent-auth.signing.private_key', $this->generateRsaPrivateKey());
        $app['config']->set('agent-auth.cache_store', 'array');
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
    }

    protected function setUpDatabase(): void
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

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password')->nullable();
            $table->rememberToken();
            $table->timestamps();
        });

        Schema::create('password_reset_tokens', function (Blueprint $table): void {
            $table->string('email')->primary();
            $table->string('token');
            $table->timestamp('created_at')->nullable();
        });

        Schema::create('sessions', function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->longText('payload');
            $table->integer('last_activity')->index();
        });
    }

    private function generateRsaPrivateKey(): string
    {
        $res = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($res, $privateKey);

        return $privateKey;
    }
}
