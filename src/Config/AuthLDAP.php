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
use CodeIgniter\Shield\Authentication\LDAP\LDAPConnection;
use CodeIgniter\Shield\Exceptions\LDAPException;

class AuthLDAP extends BaseConfig
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
     * @throws LDAPException
     */
    public function getConnection(string $id): LDAPConnection
    {
        $connection = $this->connections()[$id] ?? null;

        if ($connection === null || $connection->id !== $id) {
            throw new LDAPException('invalid_configuration');
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
     * @return array<string, LDAPConnection>
     */
    protected function connections(): array
    {
        return [];
    }
}
