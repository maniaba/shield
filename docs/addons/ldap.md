# LDAP and Active Directory authentication

Shield can verify web login credentials against an LDAPv3 directory and use its
normal Session authenticator, login actions, users, and authorization checks.
LDAP is opt-in and requires PHP's `ldap` extension. Follow the regular
[Shield installation](../getting_started/install.md) before configuring LDAP.

## Directory and TLS prerequisites

1. Create a read-only service account. Give it access to the configured search
   base, login attributes, immutable identifier, and any attributes used by
   eligibility rules or profile mappings.
2. Install a current build of the PHP LDAP extension linked against OpenLDAP in
   the PHP process that serves the application. Confirm it is loaded with
   `php --ri ldap` in the CLI and in the web runtime.
3. Configure the OpenLDAP client trust store before starting PHP. For example,
   set the following in the client configuration file used by PHP (commonly
   `/etc/ldap/ldap.conf`):

    ```text
    TLS_CACERT /etc/ssl/certs/corporate-ldap-ca.pem
    TLS_REQCERT demand
    TLS_REQSAN demand
    ```

    A service manager can also supply `LDAPTLS_CACERT` as a process environment
    variable. Mount a trusted CA bundle in the runtime and restart PHP workers
    after changing their trust configuration. The native transport uses one
    process-wide trust policy. All endpoints must present a trusted chain and a
    certificate valid for the configured hostname. [OpenLDAP TLS reference](https://www.openldap.org/doc/admin26/tls.html)

Use LDAPS for an endpoint that negotiates TLS as soon as it accepts a connection
(commonly port 636). Use StartTLS for an endpoint that upgrades LDAP to TLS before
either bind (commonly port 389). Shield refuses plaintext simple binds and does
not chase LDAP referrals.

## Configure Active Directory

Create **app/Config/AuthLdap.php**. Load the service-account secret from the
environment or from your secrets provider. Keep it out of source control and
application diagnostics.

```php
<?php

declare(strict_types=1);

namespace Config;

use CodeIgniter\Shield\Authentication\LDAP\LdapConnection;
use CodeIgniter\Shield\Config\AuthLdap as ShieldAuthLdap;

class AuthLdap extends ShieldAuthLdap
{
    public string $defaultConnection = 'corporate';

    protected function connections(): array
    {
        return [
            'corporate' => new LdapConnection(
                id: 'corporate',
                hosts: ['dc01.example.com', 'dc02.example.com'],
                baseDn: 'DC=example,DC=com',
                bindDn: 'CN=shield-reader,OU=Service Accounts,DC=example,DC=com',
                bindPassword: static fn (): string => (string) env('LDAP_CORPORATE_BIND_PASSWORD'),
                encryption: 'ldaps',
                userBaseDn: 'OU=Users,DC=example,DC=com',
                loginFilter: '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                loginAttributes: ['sAMAccountName', 'userPrincipalName'],
                externalIdAttribute: 'objectGUID',
                profileAttributes: ['username' => 'sAMAccountName'],
                provisionUsers: true,
            ),
        ];
    }
}
```

Supply `LDAP_CORPORATE_BIND_PASSWORD` to the PHP process and set
`authldap.enabled = true` in your CodeIgniter `.env` file. A service account that
can only read the necessary entries and attributes is sufficient.

List endpoints in preferred order within a connection. Each endpoint in that
list must reach the same logical directory and enforce equivalent access rules.
To route UPNs to different directory configurations, map their lower-case domain
suffixes to connection IDs in `$loginDomains`. For example, `['research.example.org'
=> 'research']` routes `alice@research.example.org` to the `research` connection.
The default connection handles unqualified logins and unmapped suffixes. The
submitted value remains the lookup value, including any suffix.

The connection factory runs on demand so its secret provider stays out of
CodeIgniter's configuration cache.

## Configure OpenLDAP

In the configuration above, set `$defaultConnection` to `'openldap'` and use
the following array in `connections()`. Supply
`LDAP_OPENLDAP_BIND_PASSWORD` to the PHP process. The server must support the
StartTLS extension on the port you configure.

```php
return [
    'openldap' => new LdapConnection(
        id: 'openldap',
        hosts: ['ldap.example.org'],
        baseDn: 'dc=example,dc=org',
        bindDn: 'cn=shield-reader,ou=services,dc=example,dc=org',
        bindPassword: static fn (): string => (string) env('LDAP_OPENLDAP_BIND_PASSWORD'),
        encryption: 'starttls',
        userBaseDn: 'ou=people,dc=example,dc=org',
        loginFilter: '(objectClass=inetOrgPerson)',
        loginAttributes: ['uid'],
        externalIdAttribute: 'entryUUID',
        profileAttributes: ['username' => 'uid'],
        provisionUsers: true,
    ),
];
```

For another LDAPv3 directory, configure the login attributes, entry filter, and
immutable identifier according to its schema. The configured identifier must
be unique, readable, and stable across user renames and moves.

## Enable Shield web login

In **app/Config/Auth.php**, configure the existing `session` alias to use
`CodeIgniter\Shield\Authentication\Authenticators\Ldap::class`. Keep your
other aliases and the existing default authenticator and chain. Set
`$validFields` to `['username']`. The bundled login form accepts both simple
usernames and UPNs. If you override the view or validation rules, use a text
field named `username` and keep your rules compatible with directory login
identifiers. Keep the action routes and normal session filters in place.

For example, add these assignments to the application `Auth` constructor after
calling `parent::__construct()`:

```php
$this->authenticators['session'] = \CodeIgniter\Shield\Authentication\Authenticators\Ldap::class;
$this->validFields = ['username'];
$this->allowRegistration = false;
$this->allowMagicLinkLogins = false;
$this->sessionConfig['allowRemembering'] = false;
```

Register the normal Shield routes. An LDAP-only application can omit the public
registration and magic-link routes in **app/Config/Routes.php**:

```php
service('auth')->routes($routes, ['except' => ['register', 'magic-link']]);
```

Use session-based CSRF protection and apply Shield's `auth-rates` filter to
login and authentication action routes. [Shield controller filters](../references/controller_filters.md#rate-limiting)

## Login eligibility

The directory evaluates an administrator-defined login filter together with
equality tests for the configured login attributes. For Active Directory, use
`sAMAccountName` or `userPrincipalName`. For OpenLDAP, use an attribute such as
`uid`. Case matching follows the directory attribute's equality rule. Shield
requires one eligible match and escapes the submitted value as an LDAP filter
assertion. Keep raw filter syntax restricted to trusted configuration.

This Active Directory filter excludes disabled accounts and requires transitive
membership in `Shield Users`. It can be configured as the `eligibilityFilter`
and is checked on the matched user after a successful user bind:

```ldap
(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf:1.2.840.113556.1.4.1941:=CN=Shield Users,OU=Groups,DC=example,DC=com))
```

Confirm that `Shield Users` is the intended security group, and test nested and
primary group membership behavior in your directory. Active Directory's
`memberOf` matching follows its directory links. For OpenLDAP with a `memberOf`
overlay, a direct eligibility filter can use
`(&(objectClass=inetOrgPerson)(memberOf=cn=shield-users,ou=groups,dc=example,dc=org))`.
Any OpenLDAP nested membership rule depends on the installed directory schema
and overlays. [Active Directory matching rules](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax)

Grouping operators `&`, `|`, and `!` can be nested. LDAP filter values use
[RFC 4515](https://www.rfc-editor.org/rfc/rfc4515) escaping. If a filter compares
a distinguished name, first encode the distinguished name according to
[RFC 4514](https://www.rfc-editor.org/rfc/rfc4514), then encode that string as a
filter assertion. An escaped comma in a DN, for example `CN=Family\, Given`, is
written as `CN=Family\5c, Given` in a filter assertion.

## Provisioning and migration from local accounts

The link between a directory account and a Shield user is scoped to a connection
ID and an immutable directory identifier. Use `objectGUID` for Active Directory
or `entryUUID` for OpenLDAP. Keep connection IDs stable. Replicas for a single
directory belong to the same connection. Give independent directories separate
connection IDs, even when their users have similar login attributes.

For a new application, enable just-in-time provisioning to create a Shield user
after the directory verifies the password. Map the local `username` field to a
single-valued directory attribute that produces valid, unique Shield usernames
of at most 30 characters. To map additional attributes, create columns and
permit them in your [custom user provider](../customization/user_provider.md).
For example, map `directory_email` to `mail` and `first_name` to `givenName`.
Unconfigured fields stay under application control. Profile attributes used by
application security decisions should be writable by trusted directory
administrators only. Set `updateProfile: false` on the connection to use the
configured attributes at provisioning only.

For a migration, start with provisioning disabled. From a trusted operator
workflow, verify the account in the directory and confirm which Shield user
should own it. Then explicitly link the two identities:

```php
use CodeIgniter\Shield\Authentication\LDAP\LdapUserResolver;

$resolver = new LdapUserResolver(auth()->getProvider());
$resolver->link('corporate', '00112233-4455-6677-8899-aabbccddeeff', 42);
```

The example uses a canonical AD GUID and Shield user ID `42`. Convert the
16-byte LDAP `objectGUID` value with `LdapUserResolver::normalizeObjectGuid()`
when reading it directly from LDAP. Use the `entryUUID` string as returned by
OpenLDAP. A link conflicts if the same directory identity is already linked
to another Shield user. Renaming an account or moving it to a new DN preserves
the link as long as the updated account still meets the directory search and
eligibility configuration. A conflicting username during attribute updates
blocks the login until the conflict is resolved. The resolver owns a database
transaction for each write operation. Call it outside other transactions on
the Shield database connection.

Shield never saves the submitted LDAP password or overwrites an existing local
password. Directory email belongs in an application profile attribute if you
need it. Use an independently verified contact method for Shield's email-based
login action, or choose an action that supports directory-only users without an
email identity. Review [Shield authentication actions](../references/authentication/auth_actions.md)
before enabling just-in-time provisioning. If registration activation is
configured, a newly provisioned account remains blocked until the application
activates it through its trusted activation workflow.

## Local-only, LDAP-only, and hybrid login

For local-only login, keep the ordinary `Session` authenticator under the
`session` alias. For LDAP-only login, configure `Ldap` as described above and
leave `$localAccounts` empty. An application can enable hybrid login by listing
the exact identifiers and corresponding Shield user IDs assigned to local
password login in **app/Config/AuthLdap.php**:

```php
public array $localAccounts = ['local-operator' => 10];
```

Reserve these identifiers for local users. An exact match always uses Shield's
local password verifier for the specified user ID. Every other identifier goes
to its selected LDAP connection. Directory credential failures and directory
outages both deny a new LDAP login. Test an emergency account with the directory
unavailable. Keep it subject to the application's configured Shield login
actions and protect its credentials independently of the directory.

## Availability and session revocation

LDAP password login verifies the submitted credentials with the directory.
The authenticator disables remember-me token issuance on password login. Keep
`allowRemembering` disabled if previous installations issued remember-me cookies
and users must prove their directory credentials on the next sign-in. Revoke
pre-migration remember-me tokens before re-enabling the feature.

Directory eligibility is checked during password login. Existing Shield
sessions and issued API tokens follow their existing lifetime and revocation
policies. When disabling a directory account, also revoke affected application
sessions and tokens using the application's established procedures. If LDAP is
the sole permitted web sign-in method, disable public registration and magic
link routes in Shield, and review any custom password reset, login, or token
issuance routes that could provide another sign-in path.

## Administrative diagnostics

Application services can use the directory transport to test configured
connections and preview a bounded search without provisioning users or changing
authorization. Restrict administrative endpoints with application authorization,
CSRF protection, and rate limits. Request only the attributes an operator needs,
and keep raw results out of ordinary application logs.

```php
use CodeIgniter\Shield\Authentication\LDAP\LdapException;
use CodeIgniter\Shield\Authentication\LDAP\LdapFilter;

$config = config('AuthLdap');
$connectionIds = $config->connectionIds();
$directory = service('ldapDirectory');

try {
    $connection = $config->getConnection('corporate');
    $directory->testConnection($connection);
    $directory->testBind($connection);

    $entries = $directory->preview(
        $connection,
        $connection->userBaseDn ?? $connection->baseDn,
        LdapFilter::all($connection->loginFilter, $connection->eligibilityFilter),
        ['sAMAccountName', 'displayName'],
        20,
    );
} catch (LdapException $exception) {
    log_message('warning', 'LDAP diagnostic failed ({reason}).', ['reason' => $exception->reason]);
}
```

Use a configured group search base and a trusted group filter with the same
`preview()` method to inspect groups. For a specific identifier, combine the
trusted filter with `LdapFilter::equal($attribute, $identifier)`. LDAP attribute
names in returned entries are lower-case and values may be binary. To test user
credentials without creating a Shield user, call the directory's `authenticate()`
method with that exact-match filter, the password, and the configured eligibility
filter. Prompt for the password, pass it directly to that method, and discard it
after the operation. The application login uses `auth('session')->attempt()`
so configured login actions can complete through Shield.

To fetch connection settings from a database or another application source,
override `AuthLdap::getConnection()` and `AuthLdap::connectionIds()`. Return a
validated `LdapConnection` and resolve its bind secret server-side. Present only
connection IDs and the operational metadata your administrators need.

### Troubleshooting

- For connection or TLS errors, confirm DNS, port, certificate chain, hostname,
  and the CA bundle loaded by the web runtime. `ldapsearch -H
  ldaps://dc01.example.com:636 -x -D '{bind DN}' -W -b 'DC=example,DC=com'
  -s base '(objectClass=*)' dn` prompts for the service password. For StartTLS,
  use an `ldap://` URI and `-ZZ` to require the upgrade.
- For a service bind failure, verify the service DN, secret, and directory policy.
  For a missing or incomplete result, verify the search base, access controls,
  filters, and timeout settings. Keep searches within the correct naming context
  since referrals are rejected.
- If a credential check succeeds but Shield login still fails, check for a
  missing link, a disabled provisioning policy, a conflicting username, or a
  local account ban or activation requirement. LDAP-specific logs use reason
  codes, and the browser receives Shield's generic login error message.

## Authorization and scope

Directory group filters can restrict eligibility to sign in. Manage Shield
authorization groups and permissions through the ordinary
[Shield authorization APIs](../references/authorization.md). Directory group
assignments, group ownership and revocation, scheduled synchronization, and
continuous revalidation are outside this contribution.

## Testing against OpenLDAP

The regular PHPUnit suite does not need a running directory. The optional
`NativeLdapDirectoryIntegrationTest` uses the disposable OpenLDAP fixture in
`tests/_support/LDAP`. With Docker, OpenSSL, the PHP LDAP extension, and the test
dependencies available, run the following from the Shield checkout:

```bash
tls_dir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -noenc -days 2 \
  -subj '/CN=Shield LDAP test CA' -addext 'basicConstraints=critical,CA:TRUE' \
  -keyout "$tls_dir/ca.key" -out "$tls_dir/ca.pem"
openssl req -newkey rsa:2048 -noenc -subj '/CN=Shield LDAP fixture' \
  -keyout "$tls_dir/server.key" -out "$tls_dir/server.csr"
printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$tls_dir/server.ext"
openssl x509 -req -days 2 -in "$tls_dir/server.csr" -CA "$tls_dir/ca.pem" \
  -CAkey "$tls_dir/ca.key" -CAcreateserial -extfile "$tls_dir/server.ext" \
  -out "$tls_dir/server.pem"

docker build -t shield-openldap-test tests/_support/LDAP
docker run --rm --detach --name shield-openldap-test \
  -p 127.0.0.1:23890:1389 -p 127.0.0.1:26360:1636 \
  --mount "type=bind,src=$tls_dir,dst=/tls,readonly" shield-openldap-test
timeout 20 bash -c 'until [ "$(docker inspect --format "{{.State.Health.Status}}" shield-openldap-test)" = healthy ]; do sleep 1; done'

LDAPTLS_CACERT="$tls_dir/ca.pem" LDAPTLS_REQCERT=demand LDAPTLS_REQSAN=demand \
  SHIELD_LDAP_TEST_PORT=23890 SHIELD_LDAP_TEST_LDAPS_PORT=26360 \
  SHIELD_LDAP_TEST_WRONG_HOST=localhost \
  SHIELD_LDAP_TEST_UNTRUSTED_CA=/etc/ssl/certs/ca-certificates.crt \
  vendor/bin/phpunit --filter NativeLdapDirectoryIntegrationTest

docker stop shield-openldap-test
```

The fixture uses test credentials and a CA valid for two days. Keep its ports
on loopback. If your operating system uses a different path for its CA bundle,
use that path for the untrusted-chain test. The bundle must exclude the
fixture's CA. The optional fixture exercises the PHP transport. Test AD-specific
GUID, account filters, and transitive group membership separately against a
disposable AD DS or Samba AD test domain.
