<?php

declare(strict_types=1);

/**
 * This file is part of CodeIgniter Shield.
 *
 * (c) CodeIgniter Foundation <admin@codeigniter.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace CodeIgniter\Shield\Authentication;

use CodeIgniter\I18n\Time;
use CodeIgniter\Shield\Authentication\JWT\Exceptions\InvalidTokenException;
use CodeIgniter\Shield\Authentication\JWT\JWSDecoder;
use CodeIgniter\Shield\Authentication\JWT\JWSEncoder;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Exceptions\RuntimeException;
use CodeIgniter\Shield\Models\JWTRevocationModel;
use RuntimeException as NativeRuntimeException;
use stdClass;

/**
 * JWT Manager
 */
class JWTManager
{
    private const SESSION_SCOPE = 'shield_session_id';

    protected Time $clock;
    protected JWSEncoder $jwsEncoder;
    protected JWSDecoder $jwsDecoder;

    public function __construct(
        ?Time $clock = null,
        ?JWSEncoder $jwsEncoder = null,
        ?JWSDecoder $jwsDecoder = null,
        private readonly ?JWTRevocationModel $revocationModel = null,
    ) {
        $this->clock      = $clock ?? new Time();
        $this->jwsEncoder = $jwsEncoder ?? new JWSEncoder(null, $this->clock);
        $this->jwsDecoder = $jwsDecoder ?? new JWSDecoder();
    }

    /**
     * Issues Signed JWT (JWS) for a User
     *
     * @param array                      $claims  The payload items.
     * @param int|null                   $ttl     Time to live in seconds.
     * @param string                     $keyset  The key group.
     *                                            The array key of Config\AuthJWT::$keys.
     * @param array<string, string>|null $headers An array with header elements to attach.
     */
    public function generateToken(
        User $user,
        array $claims = [],
        ?int $ttl = null,
        $keyset = 'default',
        ?array $headers = null,
    ): string {
        $payload = array_merge(
            $claims,
            [
                'sub' => (string) $user->id, // subject
            ],
        );

        return $this->issue($payload, $ttl, $keyset, $headers);
    }

    /**
     * Issues a JWT bound to the current authenticated browser session.
     *
     * The first JWT fixes the scope deadline. Subsequent JWTs are capped at
     * that deadline, and a later scope can begin once the deadline has passed.
     *
     * @throws AuthenticationException If no eligible browser user is logged in.
     * @throws RuntimeException        If the scope cannot be used for issuance.
     */
    public function generateSessionToken(?int $ttl = null, string $keyset = 'default'): string
    {
        $user = auth('session')->user();
        if ($user === null || $user->id === null || $user->isBanned() || ! $user->isActivated()) {
            throw AuthenticationException::forInvalidUser();
        }

        $session      = session();
        $sessionField = setting('Auth.sessionConfig')['field'];
        $userInfo     = $session->get($sessionField);
        $userId       = $userInfo['id'] ?? null;

        if ((! is_int($userId) && ! is_string($userId)) || (string) $userId !== (string) $user->id) {
            throw AuthenticationException::forInvalidUser();
        }

        $now = $this->clock::now()->getTimestamp();
        $ttl ??= config('AuthJWT')->timeToLive;

        if ($ttl < 1 || $now > PHP_INT_MAX - $ttl) {
            throw new RuntimeException('JWT session token lifetime is invalid.');
        }

        $requestedExpiry = $now + $ttl;
        $scope           = $userInfo[self::SESSION_SCOPE] ?? null;
        $scopeExpiry     = 0;

        if ($scope !== null && (! is_string($scope) || ($scopeExpiry = $this->scopeExpiry($scope)) === null)) {
            throw new RuntimeException('JWT session scope is invalid.');
        }

        if ($scope === null || $scopeExpiry <= $now) {
            $scopeExpiry = $requestedExpiry;
            // The deadline is part of the identifier, so it cannot be extended for this scope.
            $scope = sprintf('%016x', $scopeExpiry) . bin2hex(random_bytes(24));

            $userInfo[self::SESSION_SCOPE] = $scope;
            $session->set($sessionField, $userInfo);
        }

        try {
            $revoked = $this->revocations()->isRevoked($this->scopeDigest($scope));
        } catch (NativeRuntimeException) {
            throw new RuntimeException('JWT session revocation could not be checked.');
        }

        if ($revoked) {
            throw new RuntimeException('JWT session scope is revoked.');
        }

        $expiresAt = min($requestedExpiry, $scopeExpiry);
        if ($expiresAt <= $this->clock::now()->getTimestamp()) {
            throw new RuntimeException('JWT session scope expired during issuance.');
        }

        return $this->generateToken($user, [
            self::SESSION_SCOPE => $scope,
            'iat'               => $now,
            'exp'               => $expiresAt,
        ], keyset: $keyset);
    }

    /**
     * Revokes JWTs bound to the current browser session.
     *
     * The session data stays available for retry or for the caller to log out.
     *
     * @throws RuntimeException If the scope is invalid or storage fails.
     */
    public function revokeCurrentSessionTokens(): void
    {
        $scope = session(setting('Auth.sessionConfig')['field'])[self::SESSION_SCOPE] ?? null;
        if ($scope === null) {
            return;
        }

        if (! is_string($scope) || ($expiresAt = $this->scopeExpiry($scope)) === null) {
            throw new RuntimeException('JWT session scope is invalid.');
        }

        if ($expiresAt <= $this->clock::now()->getTimestamp()) {
            return;
        }

        try {
            $this->revocations()->revoke($this->scopeDigest($scope), $expiresAt);
        } catch (NativeRuntimeException) {
            throw new RuntimeException('JWT session revocation could not be stored.');
        }
    }

    /**
     * Issues Signed JWT (JWS)
     *
     * @param array                      $claims  The payload items.
     * @param int|null                   $ttl     Time to live in seconds.
     * @param string                     $keyset  The key group.
     *                                            The array key of Config\AuthJWT::$keys.
     * @param array<string, string>|null $headers An array with header elements to attach.
     */
    public function issue(
        array $claims,
        ?int $ttl = null,
        $keyset = 'default',
        ?array $headers = null,
    ): string {
        if (! array_key_exists('jti', $claims)) {
            $claims['jti'] = bin2hex(random_bytes(16));
        }

        return $this->jwsEncoder->encode($claims, $ttl, $keyset, $headers);
    }

    /**
     * Verifies the JWT and returns its payload unless it has been revoked.
     *
     * @param string $keyset The key group. The array key of Config\AuthJWT::$keys.
     */
    public function parse(string $encodedToken, $keyset = 'default'): stdClass
    {
        $payload = $this->jwsDecoder->decode($encodedToken, $keyset);

        // Keep signed JWTs issued before token IDs were added usable.
        if (! property_exists($payload, 'jti') && ! property_exists($payload, self::SESSION_SCOPE)) {
            return $payload;
        }

        [$identifier, $expiresAt] = $this->revocationIdentity($payload);
        $scopeIdentifier          = $this->signedScopeDigest($payload, $expiresAt);

        try {
            $revoked = $scopeIdentifier === null
                ? $this->revocations()->isRevoked($identifier)
                : $this->revocations()->isAnyRevoked([$identifier, $scopeIdentifier]);
        } catch (NativeRuntimeException) {
            log_message('error', '[Shield] JWT revocation lookup failed.');
            $revoked = true;
        }

        if ($revoked) {
            throw new InvalidTokenException(lang('Auth.invalidJWT'), InvalidTokenException::INVALID_TOKEN);
        }

        // An expired revocation record could have been removed during the lookup.
        $this->enforceExpiry($expiresAt);

        return $payload;
    }

    /**
     * Revokes a verified, unexpired JWT with a token ID.
     *
     * @throws InvalidTokenException If the JWT is invalid or cannot be revoked.
     * @throws RuntimeException      If storage fails.
     */
    public function revokeToken(string $encodedToken, string $keyset = 'default'): void
    {
        // Verify again without checking the revocation store so retries are safe.
        $payload                  = $this->jwsDecoder->decode($encodedToken, $keyset);
        [$identifier, $expiresAt] = $this->revocationIdentity($payload);
        $this->signedScopeDigest($payload, $expiresAt);

        try {
            $this->revocations()->revoke($identifier, $expiresAt);
        } catch (NativeRuntimeException) {
            throw new RuntimeException('JWT revocation could not be stored.');
        }
    }

    /**
     * Removes revocation records whose signed JWTs have expired.
     *
     * @return int The number of removed records.
     *
     * @throws RuntimeException If the revocation records cannot be removed.
     */
    public function purgeExpiredRevocations(): int
    {
        try {
            return $this->revocations()->purgeExpired($this->clock::now()->getTimestamp());
        } catch (NativeRuntimeException) {
            throw new RuntimeException('Expired JWT revocations could not be purged.');
        }
    }

    /**
     * @return array{string, int} The issuer-scoped digest and expiry.
     */
    private function revocationIdentity(stdClass $payload): array
    {
        $issuer    = $payload->iss ?? null;
        $jti       = $payload->jti ?? null;
        $expiresAt = $payload->exp ?? null;

        if (! is_string($issuer) || $issuer === ''
                                 || ! is_string($jti) || $jti === '' || strlen($jti) > 255
                                 || ! is_int($expiresAt)
        ) {
            throw new InvalidTokenException(lang('Auth.invalidJWT'), InvalidTokenException::INVALID_TOKEN);
        }

        $this->enforceExpiry($expiresAt);

        return [hash('sha256', strlen($issuer) . ':' . $issuer . $jti), $expiresAt];
    }

    private function enforceExpiry(int $expiresAt): void
    {
        // The revocation store can remove this record at exp, so ignore decoder leeway here.
        if ($expiresAt <= $this->clock::now()->getTimestamp()) {
            throw new InvalidTokenException(lang('Auth.expiredJWT'), InvalidTokenException::EXPIRED_TOKEN);
        }
    }

    private function signedScopeDigest(stdClass $payload, int $expiresAt): ?string
    {
        if (! property_exists($payload, self::SESSION_SCOPE)) {
            return null;
        }

        $scope = $payload->{self::SESSION_SCOPE};

        if (! is_string($scope) || ($scopeExpiry = $this->scopeExpiry($scope)) === null || $expiresAt > $scopeExpiry) {
            throw new InvalidTokenException(lang('Auth.invalidJWT'), InvalidTokenException::INVALID_TOKEN);
        }

        return $this->scopeDigest($scope);
    }

    private function scopeExpiry(string $scope): ?int
    {
        if (preg_match('/\A[0-9a-f]{64}\z/', $scope) !== 1) {
            return null;
        }

        $expiresAt = hexdec(substr($scope, 0, 16));

        return is_int($expiresAt) && $expiresAt > 0 ? $expiresAt : null;
    }

    private function scopeDigest(string $scope): string
    {
        return hash('sha256', 'shield-session:' . $scope);
    }

    private function revocations(): JWTRevocationModel
    {
        return $this->revocationModel ?? model(JWTRevocationModel::class);
    }
}
