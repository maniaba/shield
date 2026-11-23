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

namespace CodeIgniter\Shield\Tests\Unit;

use CodeIgniter\Shield\Authentication\LDAP\LDAPConnection;
use CodeIgniter\Shield\Config\AuthLDAP;
use CodeIgniter\Shield\Exceptions\LDAPException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class AuthLDAPTest extends TestCase
{
    public function testDefaultConfigurationHasNoConnections(): void
    {
        $this->assertSame([], (new AuthLDAP())->connectionIds());
    }

    public function testFindsConfiguredConnectionsById(): void
    {
        $primary   = $this->connection('primary');
        $secondary = $this->connection('secondary');
        $config    = $this->createPartialMock(AuthLDAP::class, ['connections']);
        $config->method('connections')->willReturn(['primary' => $primary, 'secondary' => $secondary]);

        $this->assertSame(['primary', 'secondary'], $config->connectionIds());
        $this->assertSame($primary, $config->getConnection('primary'));
        $this->assertSame($secondary, $config->getConnection('secondary'));
    }

    #[DataProvider('provideRejectsInvalidConnectionIds')]
    public function testRejectsInvalidConnectionIds(string $id): void
    {
        $config = $this->createPartialMock(AuthLDAP::class, ['connections']);
        $config->method('connections')->willReturn(['alias' => $this->connection('primary')]);

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('invalid_configuration');

        $config->getConnection($id);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRejectsInvalidConnectionIds(): iterable
    {
        yield 'unknown ID' => ['unknown'];

        yield 'configured key differs from connection ID' => ['alias'];
    }

    private function connection(string $id): LDAPConnection
    {
        return new LDAPConnection($id, ['ldap.example.test'], 'dc=example,dc=test', 'cn=reader,dc=example,dc=test', 'readerPassword!');
    }
}
