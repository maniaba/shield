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

namespace CodeIgniter\Shield\Authentication\LDAP;

interface LdapDirectoryInterface
{
    /**
     * Check that the configured endpoint can establish and verify TLS.
     */
    public function testConnection(LdapConnection $connection): void;

    /**
     * Check that an endpoint accepts the configured service account.
     */
    public function testBind(LdapConnection $connection): void;

    /**
     * Search for one user, verify their password, and apply the eligibility filter.
     *
     * @param list<string> $attributes
     *
     * @return array{dn: string, attributes: array<string, list<string>>} Attribute names are lowercase.
     */
    public function authenticate(
        LdapConnection $connection,
        string $baseDn,
        string $filter,
        array $attributes,
        string $password,
        string $eligibilityFilter = '(objectClass=*)',
    ): array;

    /**
     * Return a bounded sample using the service account.
     *
     * @param list<string> $attributes
     *
     * @return list<array{dn: string, attributes: array<string, list<string>>}> Attribute names are lowercase.
     */
    public function preview(
        LdapConnection $connection,
        string $baseDn,
        string $filter,
        array $attributes,
        int $limit = 20,
    ): array;
}
