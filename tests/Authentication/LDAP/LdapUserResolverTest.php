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

use CodeIgniter\Shield\Authentication\LDAP\LdapUserResolver;
use CodeIgniter\Shield\Exceptions\LdapException;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Shield\Tests\DatabaseTestCase;
use Config\Database;
use RuntimeException;

/**
 * @internal
 */
final class LdapUserResolverTest extends DatabaseTestCase
{
    protected $refresh = true;

    public function testProvisioningStoresOnlyTheStableDirectoryIdentity(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LdapUserResolver($users);

        $user = $resolver->resolve('corporate', 'immutable-object', ['username' => 'DirUser'], true);

        $this->assertSame('diruser', $user->username);
        $this->assertNull($user->email);
        $this->assertNull($user->password_hash);

        $this->seeInDatabase($this->tables['identities'], [
            'user_id' => $user->id,
            'type'    => LdapUserResolver::ID_TYPE,
            'name'    => 'corporate',
            'secret'  => hash('sha256', "corporate\0immutable-object"),
            'secret2' => null,
        ]);
        $this->seeNumRecords(1, $this->tables['identities'], ['user_id' => $user->id]);
    }

    public function testEntryRenameChangesOnlyTheConfiguredProfile(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LdapUserResolver($users);
        $user     = $resolver->resolve('corporate', 'immutable-object', ['username' => 'original'], true);

        $users->update($user->id, ['status_message' => 'Local account note']);

        $this->assertSame('original', $resolver->resolve(
            'corporate',
            'immutable-object',
            ['username' => 'renamed'],
            updateProfile: false,
        )->username);

        $renamed = $resolver->resolve('corporate', 'immutable-object', ['username' => 'renamed']);

        $this->assertSame($user->id, $renamed->id);
        $this->assertSame('renamed', $renamed->username);
        $this->assertSame('Local account note', $renamed->status_message);
        $this->seeNumRecords(1, $this->tables['identities'], ['user_id' => $user->id]);
    }

    public function testUsernameCollisionDoesNotLinkToLocalAccount(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LdapUserResolver($users);

        $userId = $users->insert(['username' => 'Existing']);

        try {
            $resolver->resolve('corporate', 'immutable-object', ['username' => 'existing'], true);
            $this->fail('A colliding username was accepted.');
        } catch (LdapException $exception) {
            $this->assertSame('identity_conflict', $exception->reason);
        }

        $this->seeNumRecords(1, $this->tables['users'], ['id' => $userId]);
        $this->dontSeeInDatabase($this->tables['identities'], ['type' => LdapUserResolver::ID_TYPE]);
    }

    public function testCustomProviderCanSynchronizeAWritableProfileColumn(): void
    {
        $users = new class () extends UserModel {
            protected $allowedFields = ['username', 'first_name'];
        };

        $forge = Database::forge($users->builder()->db());
        $this->assertTrue($forge->addColumn($this->tables['users'], [
            'first_name' => ['type' => 'varchar', 'constraint' => 100, 'null' => true],
        ]));

        $resolver = new LdapUserResolver($users);
        $user     = $resolver->resolve('corporate', 'immutable-object', [
            'username'   => 'directory',
            'first_name' => 'Initial',
        ], true);
        $changed = $resolver->resolve('corporate', 'immutable-object', ['first_name' => 'Updated']);

        $this->assertSame($user->id, $changed->id);
        $this->assertSame('Updated', $changed->first_name);
        $this->assertSame('directory', $changed->username);
    }

    public function testConnectionScopesExternalIdentity(): void
    {
        $resolver = new LdapUserResolver(model(UserModel::class));

        $corporate = $resolver->resolve('corporate', 'shared-id', ['username' => 'corporate.user'], true);
        $partner   = $resolver->resolve('partner', 'shared-id', ['username' => 'partner.user'], true);

        $this->assertNotSame($corporate->id, $partner->id);
        $this->assertSame($corporate->id, $resolver->resolve('corporate', 'shared-id')->id);
        $this->assertSame($partner->id, $resolver->resolve('partner', 'shared-id')->id);
    }

    public function testExplicitLinkIsIdempotentAndPreservesTheLocalPassword(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LdapUserResolver($users);

        $userId = $users->insert($users->createNewUser([
            'username' => 'existing',
            'email'    => 'existing@example.test',
            'password' => 'local-password',
        ]));
        $user = $users->findById($userId);

        $resolver->link('corporate', 'immutable-object', $userId);
        $resolver->link('corporate', 'immutable-object', $userId);
        $resolved = $resolver->resolve('corporate', 'immutable-object');

        $this->assertSame($user->id, $resolved->id);
        $this->assertSame($user->email, $resolved->email);
        $this->assertSame($user->password_hash, $resolved->password_hash);
        $this->assertTrue(password_verify('local-password', $resolved->password_hash));
        $this->seeNumRecords(1, $this->tables['identities'], [
            'user_id' => $userId,
            'type'    => LdapUserResolver::ID_TYPE,
        ]);
    }

    public function testCannotMoveAnExistingDirectoryIdentityToAnotherUser(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LdapUserResolver($users);
        $user     = $resolver->resolve('corporate', 'immutable-object', ['username' => 'directory'], true);
        $otherId  = $users->insert(['username' => 'another']);

        try {
            $resolver->link('corporate', 'immutable-object', $otherId);
            $this->fail('A linked identity was reassigned.');
        } catch (LdapException $exception) {
            $this->assertSame('identity_conflict', $exception->reason);
        }

        $this->assertSame($user->id, $resolver->resolve('corporate', 'immutable-object')->id);
    }

    public function testUnlinkedUserIsRejectedWhenProvisioningIsOff(): void
    {
        $resolver = new LdapUserResolver(model(UserModel::class));

        $this->expectException(LdapException::class);
        $this->expectExceptionMessage('user_not_provisioned');

        $resolver->resolve('corporate', 'immutable-object', ['username' => 'directory']);
    }

    public function testProvisioningRollsBackWhenIdentityCannotBeStored(): void
    {
        $identities = $this->getMockBuilder(UserIdentityModel::class)->onlyMethods(['create'])->getMock();
        $identities->expects($this->once())->method('create')->willThrowException(new RuntimeException('private data'));
        $resolver = new LdapUserResolver(model(UserModel::class), $identities);

        try {
            $resolver->resolve('corporate', 'immutable-object', ['username' => 'rolledback'], true);
            $this->fail('Provisioning succeeded without recording an identity.');
        } catch (LdapException $exception) {
            $this->assertSame('synchronization_conflict', $exception->reason);
            $this->assertNull($exception->getPrevious());
            $this->assertStringNotContainsString('private data', $exception->getMessage());
        }

        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'rolledback']);
    }

    public function testFailedDirectoryWriteDoesNotPoisonTheSharedConnection(): void
    {
        $users      = model(UserModel::class);
        $identities = model(UserIdentityModel::class);
        $failed     = $this->getMockBuilder(UserIdentityModel::class)->onlyMethods(['create'])->getMock();
        $failed->expects($this->once())->method('create')->willReturnCallback(static function (array $identity) use ($identities): void {
            $identities->create($identity);
            $identities->create($identity);
        });

        $resolver = new LdapUserResolver($users, $failed);

        try {
            $resolver->resolve('corporate', 'immutable-object', ['username' => 'rolledback'], true);
            $this->fail('A duplicate LDAP identity was stored.');
        } catch (LdapException $exception) {
            $this->assertSame('synchronization_conflict', $exception->reason);
        }

        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'rolledback']);
        $this->assertTrue($users->builder()->db()->transStrict);

        $resolved = (new LdapUserResolver($users))->resolve('corporate', 'immutable-object', ['username' => 'retried'], true);

        $this->assertSame('retried', $resolved->username);
    }

    public function testProfileCannotOverwriteLocalEmailOrPassword(): void
    {
        $resolver = new LdapUserResolver(model(UserModel::class));

        $this->expectException(LdapException::class);
        $this->expectExceptionMessage('invalid_profile');

        $resolver->resolve('corporate', 'immutable-object', [
            'username' => 'directory',
            'email'    => 'directory@example.test',
        ], true);
    }

    public function testUnwritableProfileFieldRollsBackProvisioning(): void
    {
        $resolver = new LdapUserResolver(model(UserModel::class));

        try {
            $resolver->resolve('corporate', 'immutable-object', [
                'username'   => 'directory',
                'first_name' => 'First',
            ], true);
            $this->fail('The unmapped profile field was silently ignored.');
        } catch (LdapException $exception) {
            $this->assertSame('invalid_profile', $exception->reason);
        }

        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'directory']);
    }

    public function testProvisioningDoesNotJoinAnExistingTransaction(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LdapUserResolver($users);
        $database = $users->builder()->db();

        $this->assertTrue($database->transBegin());

        try {
            $resolver->resolve('corporate', 'immutable-object', ['username' => 'directory'], true);
            $this->fail('The resolver joined the active transaction.');
        } catch (LdapException $exception) {
            $this->assertSame('synchronization_conflict', $exception->reason);
        } finally {
            $this->assertTrue($database->transRollback());
        }

        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'directory']);
    }

    public function testActiveDirectoryGuidUsesCanonicalByteOrder(): void
    {
        $bytes = hex2bin('785634123412cdab891023456789abcd');

        $this->assertSame('12345678-1234-abcd-8910-23456789abcd', LdapUserResolver::normalizeObjectGuid($bytes));
    }
}
