<?php

declare(strict_types=1);

namespace DanielPetrica\AuthMd\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

final class JwtSigningService
{
    public function __construct(
        private readonly string $algorithm,
        private readonly string $privateKey,
        private readonly string $keyId,
    ) {}

    public static function make(): self
    {
        return new self(
            algorithm: config('agent-auth.signing.algorithm', 'RSA256'),
            privateKey: config('agent-auth.signing.private_key'),
            keyId: config('agent-auth.signing.key_id', 'default'),
        );
    }

    public function sign(array $claims, string $typ = 'oauth-id-jag+jwt'): string
    {
        $header = [
            'typ' => $typ,
            'alg' => $this->getAlgHeader(),
            'kid' => $this->keyId,
        ];

        $payload = array_merge([
            'iss' => config('app.url'),
            'aud' => config('app.url'),
            'iat' => now()->timestamp,
            'exp' => now()->addHours((int) config('agent-auth.token.ttl_hours', 72))->timestamp,
        ], $claims);

        return JWT::encode($payload, $this->privateKey, $this->getJwtAlgorithm(), null, $header);
    }

    public function verify(string $token): object
    {
        return JWT::decode($token, new Key($this->getPublicKey(), $this->getJwtAlgorithm()));
    }

    /** @return array{keys: array<int, array<string, string>>} */
    public function getJwks(): array
    {
        return [
            'keys' => [
                [
                    'kid' => $this->keyId,
                    'kty' => $this->algorithm === 'Ed25519' ? 'OKP' : 'RSA',
                    'alg' => $this->getAlgHeader(),
                    'use' => 'sig',
                    ...$this->getKeyJwk(),
                ],
            ],
        ];
    }

    private function getAlgHeader(): string
    {
        return match ($this->algorithm) {
            'Ed25519' => 'EdDSA',
            'RSA256' => 'RS256',
            default => 'RS256',
        };
    }

    private function getJwtAlgorithm(): string
    {
        return match ($this->algorithm) {
            'Ed25519' => 'EdDSA',
            'RSA256' => 'RS256',
            default => 'RS256',
        };
    }

    private function getPublicKey(): string
    {
        $res = openssl_pkey_get_private($this->privateKey);
        $details = openssl_pkey_get_details($res);
        openssl_pkey_free($res);

        return $details['key'];
    }

    /** @return array<string, string> */
    private function getKeyJwk(): array
    {
        $res = openssl_pkey_get_public($this->getPublicKey());
        $details = openssl_pkey_get_details($res);
        openssl_pkey_free($res);

        if ($this->algorithm === 'Ed25519') {
            return ['x' => rtrim(strtr(base64_encode($details['ed25519']['x']), '+/', '-_'), '=')];
        }

        return [
            'n' => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
            'e' => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '='),
        ];
    }
}
