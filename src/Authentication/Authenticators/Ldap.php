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

namespace CodeIgniter\Shield\Authentication\Authenticators;

use CodeIgniter\Shield\Authentication\LDAP\LdapDirectoryInterface;
use CodeIgniter\Shield\Authentication\LDAP\LdapFilter;
use CodeIgniter\Shield\Authentication\LDAP\LdapUserResolver;
use CodeIgniter\Shield\Config\AuthLdap;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Exceptions\LdapException;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Shield\Result;

class Ldap extends Session
{
    private readonly AuthLdap $ldapConfig;
    private readonly LdapDirectoryInterface $directory;
    private readonly LdapUserResolver $resolver;

    public function __construct(
        UserModel $provider,
        ?AuthLdap $config = null,
        ?LdapDirectoryInterface $directory = null,
        ?LdapUserResolver $resolver = null,
    ) {
        parent::__construct($provider);

        $this->ldapConfig = $config ?? config('AuthLdap');
        $this->directory  = $directory ?? service('ldapDirectory');
        $this->resolver   = $resolver ?? new LdapUserResolver($provider);
    }

    /**
     * @param array<array-key, mixed> $credentials
     */
    public function attempt(array $credentials): Result
    {
        $identifier = $credentials['username'] ?? '';
        $password   = $credentials['password'] ?? '';

        if (! $this->validIdentifier($identifier) || config('Auth')->validFields !== ['username']) {
            return $this->failedResult();
        }

        // This login entry point always requires a fresh credential check.
        $this->remember(false);

        // The parent sends failed login credentials (minus password) to event listeners.
        return parent::attempt(['username' => $identifier, 'password' => is_string($password) ? $password : '']);
    }

    /**
     * @param array<array-key, mixed> $credentials
     */
    public function check(array $credentials): Result
    {
        $identifier = $credentials['username'] ?? '';
        $password   = $credentials['password'] ?? '';

        if (! $this->ldapConfig->enabled || ! $this->validIdentifier($identifier)
                                         || ! is_string($password) || $password === '' || strlen($password) > 4096 || str_contains($password, "\0")
        ) {
            return $this->failedResult();
        }

        $localId = $this->ldapConfig->localAccounts[$identifier] ?? null;
        if ($localId !== null) {
            return $this->checkLocalAccount($identifier, $password, $localId);
        }

        try {
            $user = $this->resolveUser($identifier, $password);

            if ($user->isBanned() || ! $user->isActivated()) {
                return $this->failedResult();
            }

            return new Result(['success' => true, 'extraInfo' => $user]);
        } catch (LdapException $exception) {
            log_message('debug', 'Shield LDAP login rejected ({reason}).', ['reason' => $exception->reason]);

            return $this->failedResult();
        }
    }

    /**
     * @param array<string, string> $credentials
     */
    protected function touchLoginIdentity(User $user, array $credentials): void
    {
        if (isset($this->ldapConfig->localAccounts[$credentials['username'] ?? ''])) {
            parent::touchLoginIdentity($user, $credentials);
        }
    }

    private function resolveUser(string $identifier, string $password): User
    {
        $separator    = strrpos($identifier, '@');
        $domain       = $separator === false ? '' : strtolower(substr($identifier, $separator + 1));
        $connectionId = $this->ldapConfig->loginDomains[$domain] ?? $this->ldapConfig->defaultConnection;
        $connection   = $this->ldapConfig->getConnection($connectionId);

        if ($connection->id !== $connectionId) {
            throw new LdapException('invalid_configuration');
        }

        $predicates = [];

        foreach ($connection->loginAttributes as $attribute) {
            $predicates[] = LdapFilter::equal($attribute, $identifier);
        }

        $filter = LdapFilter::all($connection->loginFilter, LdapFilter::any(...$predicates));
        $entry  = $this->directory->authenticate(
            $connection,
            $connection->userBaseDn ?? $connection->baseDn,
            $filter,
            array_values(array_unique([$connection->externalIdAttribute, ...array_values($connection->profileAttributes)])),
            $password,
            $connection->eligibilityFilter,
        );

        $ids = $entry['attributes'][strtolower($connection->externalIdAttribute)] ?? [];

        if (count($ids) !== 1 || $ids[0] === '') {
            throw new LdapException('invalid_identity');
        }

        $externalId = strcasecmp($connection->externalIdAttribute, 'objectGUID') === 0
            ? LdapUserResolver::normalizeObjectGuid($ids[0])
            : $ids[0];
        $profile = [];

        foreach ($connection->profileAttributes as $field => $attribute) {
            $values = $entry['attributes'][strtolower($attribute)] ?? [];

            if (count($values) === 1) {
                $profile[$field] = $values[0];
            } elseif ($values !== []) {
                throw new LdapException('invalid_profile');
            }
        }

        return $this->resolver->resolve(
            $connection->id,
            $externalId,
            $profile,
            $connection->provisionUsers,
            $connection->updateProfile,
        );
    }

    /**
     * @param int|string $expectedId
     */
    private function checkLocalAccount(string $identifier, string $password, $expectedId): Result
    {
        $result = parent::check(['username' => $identifier, 'password' => $password]);
        $user   = $result->extraInfo();

        if ($user instanceof User && (string) $user->id === (string) $expectedId
            && ! $user->isBanned() && $user->isActivated()
        ) {
            return $result;
        }

        return $this->failedResult();
    }

    private function validIdentifier(mixed $identifier): bool
    {
        return is_string($identifier) && $identifier !== '' && strlen($identifier) <= 255
            && preg_match('/^[^\p{Cc}]+$/uD', $identifier) === 1;
    }

    private function failedResult(): Result
    {
        return new Result(['success' => false, 'reason' => lang('Auth.badAttempt')]);
    }
}
