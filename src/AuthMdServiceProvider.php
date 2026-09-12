<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd;

use DanielPetrica\AuthMd\Services\DiscoveryService;
use DanielPetrica\AuthMd\Services\JwtSigningService;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

final class AuthMdServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/agent-auth.php',
            'agent-auth'
        );

        $this->app->singleton(DiscoveryService::class);
        $this->app->singleton(JwtSigningService::class, fn () => JwtSigningService::make());
    }

    public function boot(): void
    {
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'agent-auth');
        $this->loadTranslationsFrom(__DIR__.'/../resources/lang', 'agent-auth');

        $this->registerRoutes();
        $this->registerRateLimiter();

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/agent-auth.php' => config_path('agent-auth.php'),
            ], 'agent-auth-config');

            $this->publishes([
                __DIR__.'/../resources/views' => resource_path('views/vendor/agent-auth'),
            ], 'agent-auth-views');

            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'agent-auth-migrations');

            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }
    }

    private function registerRoutes(): void
    {
        // .well-known discovery endpoints
        Route::get('/.well-known/oauth-protected-resource', function () {
            return response()->json(app(DiscoveryService::class)->getProtectedResourceMetadata())
                ->header('Access-Control-Allow-Origin', '*');
        });

        Route::get('/.well-known/oauth-authorization-server', function () {
            return response()->json(app(DiscoveryService::class)->getAuthorizationServerMetadata())
                ->header('Access-Control-Allow-Origin', '*');
        });

        Route::get('/.well-known/jwks.json', function () {
            return response()->json(app(JwtSigningService::class)->getJwks())
                ->header('Access-Control-Allow-Origin', '*');
        });

        Route::get('/auth.md', function () {
            return response(app(DiscoveryService::class)->getAuthMarkdown())
                ->header('Content-Type', 'text/plain; charset=UTF-8');
        });

        // Package routes
        Route::group([
            'prefix' => config('agent-auth.route_prefix', ''),
            'as' => 'agent-auth.',
        ], function (): void {
            $this->loadRoutesFrom(__DIR__.'/../routes/agent-auth.php');
            $this->loadRoutesFrom(__DIR__.'/../routes/claim.php');
        });
    }

    private function registerRateLimiter(): void
    {
        $this->app[RateLimiter::class]->for('agent-auth', function (Request $request): Limit {
            return Limit::perMinutes(
                (int) config('agent-auth.rate_limits.identity_per_ip', 5),
                60
            )->by($request->ip());
        });
    }
}
