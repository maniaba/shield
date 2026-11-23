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

namespace CodeIgniter\Shield\Tests\Controllers;

use CodeIgniter\Config\Factories;
use CodeIgniter\Shield\Authentication\Actions\Email2FA;
use CodeIgniter\Shield\Authentication\Authenticators\Ldap;
use CodeIgniter\Shield\Authentication\LDAP\LdapConnection;
use CodeIgniter\Shield\Authentication\LDAP\LdapDirectoryInterface;
use CodeIgniter\Shield\Authentication\LDAP\LdapException;
use CodeIgniter\Shield\Authentication\LDAP\LdapUserResolver;
use CodeIgniter\Shield\Config\AuthLdap;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Tests\DatabaseTestCase;
use CodeIgniter\Shield\Tests\FakeUser;
use CodeIgniter\Test\FeatureTestTrait;
use Config\Services;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * @internal
 */
final class LdapLoginTest extends DatabaseTestCase
{
    use FakeUser;
    use FeatureTestTrait;

    private AuthLdap $ldap;
    private LdapDirectoryInterface&MockObject $directory;

    /**
     * @var array<string, LdapConnection>
     */
    private array $connections = [];

    protected function setUp(): void
    {
        parent::setUp();

        $auth                            = config('Auth');
        $auth->authenticators['session'] = Ldap::class;
        $auth->validFields               = ['username'];

        $config = $this->createPartialMock(AuthLdap::class, ['connections']);
        $config->method('connections')->willReturnCallback(fn (): array => $this->connections);

        $this->ldap                    = $config;
        $this->ldap->enabled           = true;
        $this->ldap->defaultConnection = 'example';
        $this->connections['example']  = new LdapConnection(
            id: 'example',
            hosts: ['ldap.example.com'],
            baseDn: 'dc=example,dc=com',
            bindDn: 'cn=reader,dc=example,dc=com',
            bindPassword: 'test-service-password',
            profileAttributes: ['username' => 'uid'],
            provisionUsers: true,
        );
        Factories::injectMock('config', 'AuthLdap', $this->ldap);

        $this->directory = $this->createMock(LdapDirectoryInterface::class);
        Services::injectMock('ldapDirectory', $this->directory);

        $routes = service('routes');
        auth()->routes($routes);
        Services::injectMock('routes', $routes);
    }

    public function testDirectoryLoginUsesShieldSessionAndDoesNotRememberPassword(): void
    {
        $this->directory->expects($this->once())->method('authenticate')->willReturn($this->entry());

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret', 'remember' => '1']);

        $response->assertStatus(302);
        $response->assertSessionMissing('error');
        $this->assertTrue(auth('session')->loggedIn());
        $user = auth('session')->user();
        $this->assertInstanceOf(User::class, $user);
        $this->assertSame('directory-user', $user->username);
        $this->assertNull($user->getEmailIdentity());
        $this->assertFalse($user->requiresPasswordReset());
        $this->seeInDatabase($this->tables['logins'], ['user_id' => $user->id, 'success' => 1]);
        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => $user->id]);
        $this->assertNull(session('_ci_old_input'));
    }

    public function testLinkedDirectoryAccountStillRequiresConfiguredLoginAction(): void
    {
        config('Auth')->actions['login'] = Email2FA::class;
        $this->user->createEmailIdentity(['email' => 'safe-contact@example.com', 'password' => 'local-password']);
        $this->user->addGroup('admin');
        (new LdapUserResolver(auth()->getProvider()))->link('example', 'stable-id', $this->user->id);
        $this->directory->expects($this->once())->method('authenticate')->willReturn($this->entry($this->user->username));

        $response = $this->post('/login', ['username' => $this->user->username, 'password' => 'directory-secret', 'remember' => '1']);

        $response->assertStatus(302);
        $this->assertSame(site_url('auth/a/show'), $response->getRedirectUrl());
        $authenticator = auth('session')->getAuthenticator();
        $this->assertInstanceOf(Ldap::class, $authenticator);
        $this->assertTrue($authenticator->isPending());
        $this->assertFalse(auth('session')->loggedIn());
        $this->assertTrue($authenticator->getPendingUser()->inGroup('admin'));
        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);
    }

    public function testReservedLocalAccountDoesNotQueryDirectory(): void
    {
        $this->user->createEmailIdentity(['email' => 'operator@example.com', 'password' => 'local-password']);
        $this->ldap->localAccounts[$this->user->username] = $this->user->id;
        $this->directory->expects($this->never())->method('authenticate');

        $response = $this->post('/login', ['username' => $this->user->username, 'password' => 'local-password']);

        $response->assertStatus(302);
        $response->assertSessionMissing('error');
        $this->assertSame($this->user->id, auth('session')->id());
    }

    #[DataProvider('provideDirectoryFailureNeverFallsBackOrFlashesPassword')]
    public function testDirectoryFailureNeverFallsBackOrFlashesPassword(string $reason): void
    {
        $this->user->createEmailIdentity(['email' => 'operator@example.com', 'password' => 'local-password']);
        $this->directory->expects($this->once())->method('authenticate')->willThrowException(new LdapException($reason));

        $response = $this->post('/login', ['username' => $this->user->username, 'password' => 'local-password']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $this->assertFalse(auth('session')->loggedIn());
        $this->assertNull(session('_ci_old_input'));
    }

    /**
     * @return iterable<list<string>>
     */
    public static function provideDirectoryFailureNeverFallsBackOrFlashesPassword(): iterable
    {
        yield ['invalid_credentials'];

        yield ['ambiguous_user'];

        yield ['tls_failed'];

        yield ['directory_unavailable'];

        yield ['ineligible_user'];
    }

    public function testEmptyPasswordFailsBeforeDirectoryAccess(): void
    {
        $this->directory->expects($this->never())->method('authenticate');

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => '']);

        $response->assertStatus(302);
        $response->assertSessionHas('errors');
        $this->assertNull(session('_ci_old_input'));
    }

    public function testDisabledAuthenticatorFailsClosed(): void
    {
        $this->ldap->enabled = false;
        $this->directory->expects($this->never())->method('authenticate');

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $this->assertFalse(auth('session')->loggedIn());
    }

    public function testUpnRoutesToNamedConnectionAndEscapesAssertionValue(): void
    {
        $connection = new LdapConnection(
            id: 'corporate',
            hosts: ['ad.example.com'],
            baseDn: 'dc=ad,dc=example,dc=com',
            bindDn: 'cn=reader,dc=ad,dc=example,dc=com',
            bindPassword: 'test-service-password',
            loginAttributes: ['sAMAccountName', 'userPrincipalName'],
            externalIdAttribute: 'objectGUID',
        );
        $this->connections['corporate']             = $connection;
        $this->ldap->loginDomains['ad.example.com'] = 'corporate';
        $this->directory->expects($this->once())->method('authenticate')->with(
            $connection,
            $connection->baseDn,
            '(&(objectClass=person)(|(sAMAccountName=a\28\2a\29@AD.EXAMPLE.COM)(userPrincipalName=a\28\2a\29@AD.EXAMPLE.COM)))',
            ['objectGUID'],
            'directory-secret',
            '(objectClass=*)',
        )->willThrowException(new LdapException('user_not_found'));

        $response = $this->post('/login', ['username' => 'a(*)@AD.EXAMPLE.COM', 'password' => 'directory-secret']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
    }

    public function testDirectoryGuidResolvesTheExplicitLinkAfterLoginRename(): void
    {
        $this->connections['example'] = new LdapConnection(
            id: 'example',
            hosts: ['ad.example.com'],
            baseDn: 'dc=ad,dc=example,dc=com',
            bindDn: 'cn=reader,dc=ad,dc=example,dc=com',
            bindPassword: 'test-service-password',
            loginAttributes: ['userPrincipalName'],
            externalIdAttribute: 'objectGUID',
        );
        (new LdapUserResolver(auth()->getProvider()))->link(
            'example',
            '00112233-4455-6677-8899-aabbccddeeff',
            $this->user->id,
        );
        $this->directory->expects($this->once())->method('authenticate')->willReturn([
            'dn'         => 'cn=New Name,dc=ad,dc=example,dc=com',
            'attributes' => ['objectguid' => ["\x33\x22\x11\x00\x55\x44\x77\x66\x88\x99\xaa\xbb\xcc\xdd\xee\xff"]],
        ]);

        $response = $this->post('/login', ['username' => 'renamed@ad.example.com', 'password' => 'directory-secret']);

        $response->assertSessionMissing('error');
        $this->assertSame($this->user->id, auth('session')->id());
    }

    /**
     * @return array{dn: string, attributes: array<string, list<string>>}
     */
    private function entry(string $uid = 'directory-user'): array
    {
        return [
            'dn'         => 'uid=' . $uid . ',dc=example,dc=com',
            'attributes' => ['uid' => [$uid], 'entryuuid' => ['stable-id']],
        ];
    }
}
