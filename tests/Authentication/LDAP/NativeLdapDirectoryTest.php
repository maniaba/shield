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

namespace CodeIgniter\Shield\Tests\Authentication\LDAP;

use ArrayObject;
use CodeIgniter\Shield\Authentication\LDAP\LdapConnection;
use CodeIgniter\Shield\Authentication\LDAP\NativeLdapDirectory;
use CodeIgniter\Shield\Exceptions\LdapException;
use CodeIgniter\Shield\Exceptions\RuntimeException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class NativeLdapDirectoryTest extends TestCase
{
    public function testRedactsBindSecretInConfigurationInspection(): void
    {
        $connection = new LdapConnection('test', ['ldap.example.test'], 'dc=example,dc=test', 'cn=reader,dc=example,dc=test', 'readerPassword!');

        $this->assertStringNotContainsString('readerPassword!', print_r($connection, true));
        $this->assertStringNotContainsString('readerPassword!', var_export($connection, true));
        $this->assertStringNotContainsString('readerPassword!', json_encode($connection, JSON_THROW_ON_ERROR));
    }

    public function testReadsBindSecretLazily(): void
    {
        $reads  = new ArrayObject();
        $secret = static function () use ($reads): string {
            $reads->append(true);

            return 'readerPassword!';
        };
        $connection = new LdapConnection('test', ['ldap.example.test'], 'dc=example,dc=test', 'cn=reader,dc=example,dc=test', $secret);

        $this->assertCount(0, $reads);
        $this->assertSame('readerPassword!', $connection->bindPassword());
        $this->assertCount(1, $reads);
    }

    public function testInvalidEndpointThrowsLocalizedShieldException(): void
    {
        $language = service('language');
        $locale   = $language->getLocale();
        $language->setLocale('sr');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('LDAP operacija nije uspela (invalid_endpoint).');

        try {
            new LdapConnection('test', ['ldap://example.test'], 'dc=example,dc=test', 'cn=reader,dc=example,dc=test', 'readerPassword!');
        } finally {
            $language->setLocale($locale);
        }
    }

    #[DataProvider('provideRejectsPasswordsBeforeContactingDirectory')]
    public function testRejectsPasswordsBeforeContactingDirectory(string $password): void
    {
        $connection = new LdapConnection('test', ['invalid.test'], 'dc=example,dc=test', 'cn=reader,dc=example,dc=test', 'readerPassword!');

        $this->expectException(LdapException::class);
        $this->expectExceptionMessage('invalid_credentials');

        (new NativeLdapDirectory())->authenticate($connection, $connection->baseDn, '(uid=alice)', [], $password);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRejectsPasswordsBeforeContactingDirectory(): iterable
    {
        yield 'empty password' => [''];

        yield 'NUL byte' => ["\0abc"];
    }
}
