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

namespace CodeIgniter\Shield\Tests\Authentication\Filters;

use CodeIgniter\Config\Factories;
use CodeIgniter\Database\Exceptions\DatabaseException;
use CodeIgniter\Filters\CSRF;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Shield\Authentication\Authenticators\JWT;
use CodeIgniter\Shield\Authentication\JWTManager;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Exceptions\RuntimeException;
use CodeIgniter\Shield\Filters\JWTAuth;
use CodeIgniter\Shield\Models\JWTRevocationModel;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Shield\Tests\DatabaseTestCase;
use CodeIgniter\Test\FeatureTestTrait;
use CodeIgniter\Test\TestResponse;
use Config\Services;

/**
 * @internal
 */
final class JWTSessionRevocationTest extends DatabaseTestCase
{
    use FeatureTestTrait;

    protected function setUp(): void
    {
        parent::setUp();

        config('Auth')->authenticators['jwt'] = JWT::class;
        config('Security')->redirect          = true;

        $filters                  = config('Filters');
        $filters->aliases['jwt']  = JWTAuth::class;
        $filters->aliases['csrf'] = CSRF::class;
        Factories::injectMock('config', 'Filters', $filters);

        $routes = service('routes');
        $routes->get('login', static fn (): string => 'Login', ['as' => 'login']);
        $routes->get('jwt-protected', static fn (): string => 'Protected', ['filter' => 'jwt']);
        $routes->post(
            'session-token',
            static fn (): ResponseInterface => service('response')->setBody(service('jwtmanager')->generateSessionToken()),
            ['filter' => 'csrf'],
        );
        $routes->post('session-logout', static function (): ResponseInterface {
            try {
                service('jwtmanager')->revokeCurrentSessionTokens();
            } catch (RuntimeException) {
                return service('response')->setStatusCode(ResponseInterface::HTTP_SERVICE_UNAVAILABLE);
            }

            auth('session')->logout();

            return service('response')->setStatusCode(ResponseInterface::HTTP_NO_CONTENT);
        }, ['filter' => 'csrf']);
        Services::injectMock('routes', $routes);
    }

    public function testLogoutRevokesOnlyTokensFromTheCurrentSession(): void
    {
        /** @var User $user */
        $user = fake(UserModel::class);

        $this->loginBrowser($user);
        $firstToken   = $this->issueSessionToken();
        $secondToken  = $this->issueSessionToken();
        $firstSession = $_SESSION;

        $this->loginBrowser($user);
        $otherSessionToken = $this->issueSessionToken();
        $independentToken  = service('jwtmanager')->generateToken($user);

        $this->assertNotSame($firstToken, $secondToken);
        $this->assertGreaterThan(255, strlen($firstToken));
        $this->assertBearerStatus($firstToken, 200);
        $this->assertBearerStatus($secondToken, 200);
        $this->assertBearerStatus($otherSessionToken, 200);
        $this->assertBearerStatus($independentToken, 200);

        $_SESSION    = $firstSession;
        $withoutCSRF = $this->postAsBrowser('session-logout', false);
        $withoutCSRF->assertRedirect();
        $withoutCSRF->assertSessionHas('error', lang('Security.disallowedAction'));
        $firstSession = $_SESSION;
        $this->assertBearerStatus($firstToken, 200);

        $_SESSION  = $firstSession;
        $loggedOut = $this->postAsBrowser('session-logout');
        $loggedOut->assertStatus(204);
        $loggedOut->assertSessionMissing('user');

        $this->assertBearerStatus($firstToken, 401);
        $this->assertBearerStatus($secondToken, 401);
        $this->assertBearerStatus($otherSessionToken, 200);
        $this->assertBearerStatus($independentToken, 200);
        $this->seeInDatabase($this->tables['token_logins'], [
            'id_type'    => JWT::ID_TYPE_JWT,
            'identifier' => 'JWT exceeds 255 characters',
            'success'    => 0,
        ]);
        $this->dontSeeInDatabase($this->tables['token_logins'], ['identifier' => $firstToken]);
    }

    public function testStorageFailurePreservesTheSessionForARetry(): void
    {
        /** @var User $user */
        $user = fake(UserModel::class);
        $this->loginBrowser($user);
        $token = $this->issueSessionToken();

        $revocations = $this->createMock(JWTRevocationModel::class);
        $revocations->expects($this->once())->method('revoke')
            ->willThrowException(new DatabaseException('Revocation storage unavailable'));
        Services::injectMock('jwtmanager', new JWTManager(revocationModel: $revocations));

        $this->postAsBrowser('session-logout')->assertStatus(503);
        $this->assertSame($user->id, session('user')['id'] ?? null);
        $browserSession = $_SESSION;

        Services::resetSingle('jwtmanager');
        $this->assertBearerStatus($token, 200);

        $_SESSION  = $browserSession;
        $loggedOut = $this->postAsBrowser('session-logout');
        $loggedOut->assertStatus(204);
        $loggedOut->assertSessionMissing('user');
        $this->assertBearerStatus($token, 401);
    }

    private function loginBrowser(User $user): void
    {
        $_SESSION = [];
        Services::resetSingle('auth');
        auth('session')->login($user);
    }

    private function issueSessionToken(): string
    {
        $result = $this->postAsBrowser('session-token');
        $result->assertStatus(200);

        $token = $result->response()->getBody();
        $this->assertIsString($token);

        return $token;
    }

    private function postAsBrowser(string $path, bool $includeCSRF = true): TestResponse
    {
        Services::resetSingle('auth');
        Services::resetSingle('security');
        $params = $includeCSRF ? [csrf_token() => csrf_hash()] : [];
        Services::resetSingle('security');

        return $this->withHeaders([])->withSession()->post($path, $params);
    }

    private function assertBearerStatus(string $token, int $status): void
    {
        Services::resetSingle('auth');

        $this->withHeaders(['Authorization' => 'Bearer ' . $token])->withSession([])
            ->get('jwt-protected')->assertStatus($status);
    }
}
