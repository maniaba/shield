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

namespace CodeIgniter\Shield\Config;

use CodeIgniter\Config\BaseConfig;
use CodeIgniter\Shield\Authentication\LDAP\LdapConnection;
use CodeIgniter\Shield\Exceptions\LdapException;

class AuthLdap extends BaseConfig
{
    public bool $enabled             = false;
    public string $defaultConnection = '';

    /**
     * @var array<string, string> Lowercase UPN suffix to connection ID.
     */
    public array $loginDomains = [];

    /**
     * @var array<string, int|string> Exact login identifier to expected local user ID.
     */
    public array $localAccounts = [];

    /**
     * Override this method to load a named connection from an application-owned provider.
     *
     * @throws LdapException
     */
    public function getConnection(string $id): LdapConnection
    {
        $connection = $this->connections()[$id] ?? null;

        if ($connection === null || $connection->id !== $id) {
            throw new LdapException('invalid_configuration');
        }

        return $connection;
    }

    /**
     * @return list<string>
     */
    public function connectionIds(): array
    {
        return array_keys($this->connections());
    }

    /**
     * Construct connections on demand so bind secrets stay out of the config cache.
     *
     * @return array<string, LdapConnection>
     */
    protected function connections(): array
    {
        return [];
    }
}
