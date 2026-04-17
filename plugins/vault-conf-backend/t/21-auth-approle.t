use strict;
use warnings;
use Test::More;
use lib 't/lib';
use MockUA;

plan skip_all =>
  "LWP::Protocol::PSGI / Plack::Request / JSON required for these tests"
  unless MockUA::deps_ok();

use_ok('Lemonldap::NG::Common::Conf');

$Lemonldap::NG::Common::Conf::msg = '';

# Helper: build approle backend (no token key)
sub approle_backend {
    my (%extra) = @_;
    return MockUA::mockBackend(
        token    => undef,
        roleId   => 'my-role',
        secretId => 'my-secret',
        %extra,
    );
}

# --- first request triggers POST /auth/approle/login ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = approle_backend();

    # Queue: login response, then load response
    MockUA::canned(
        [
            200,
            {
                auth => {
                    client_token   => 'xyz',
                    lease_duration => 300
                }
            }
        ],
        [ 200, { data => { data => { cfgNum => 5 } } } ],
    );

    my $result = $b->load(5);

    my @reqs = MockUA::requests();
    is( scalar @reqs, 2, 'two requests: login + load' );

    # First request must be login POST
    my $login_req = $reqs[0];
    is( $login_req->{method}, 'POST', 'login uses POST' );
    like(
        $login_req->{uri},
        qr{/auth/approle/login$},
        'login hits /auth/approle/login'
    );

    my $login_body = $login_req->{body};
    is( $login_body->{role_id},   'my-role',   'login body has role_id' );
    is( $login_body->{secret_id}, 'my-secret', 'login body has secret_id' );

    # Token stored
    is( $b->{_token}, 'xyz', 'client_token stored as _token' );
    cmp_ok( $b->{_tokenExp}, '>', time, '_tokenExp is in the future' );

    # Second request uses the obtained token
    my $load_req = $reqs[1];
    is( $load_req->{headers}{'X-Vault-Token'}, 'xyz',
        'load request uses token xyz' );

    # Result check
    is_deeply( $result, { cfgNum => 5 }, 'load returns correct data' );
}

# --- subsequent requests reuse stored token (no re-login) ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = approle_backend();

    # Pre-seed a valid token with plenty of expiry
    $b->{_token}    = 'cached-token';
    $b->{_tokenExp} = time + 3600;

    MockUA::canned( [ 200, { data => { data => { cfgNum => 7 } } } ] );

    $b->load(7);

    is( MockUA::requestCount(), 1, 'only one request — no re-login' );
    is(
        MockUA::lastRequest()->{headers}{'X-Vault-Token'},
        'cached-token',
        'uses cached token'
    );
}

# --- re-login triggered when token is about to expire (< 30s left) ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = approle_backend();

    # Token near expiry
    $b->{_token}    = 'old-token';
    $b->{_tokenExp} = time + 10;    # < 30 s

    MockUA::canned(
        [
            200,
            {
                auth => {
                    client_token   => 'new-token',
                    lease_duration => 300
                }
            }
        ],
        [ 200, { data => { data => { cfgNum => 3 } } } ],
    );

    $b->load(3);

    my @reqs = MockUA::requests();
    is( scalar @reqs, 2, 'two requests: re-login + load' );
    is( $reqs[0]{method}, 'POST', 'first request is login POST' );
    like(
        $reqs[0]{uri},
        qr{/auth/approle/login$},
        're-login hits /auth/approle/login'
    );
    is(
        $reqs[1]{headers}{'X-Vault-Token'},
        'new-token',
        'load uses new token after re-login'
    );
}

# --- custom approleMount ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = approle_backend( approleMount => 'baz' );

    MockUA::canned(
        [
            200,
            {
                auth => {
                    client_token   => 'tok2',
                    lease_duration => 300
                }
            }
        ],
        [ 200, { data => { data => { cfgNum => 9 } } } ],
    );

    $b->load(9);

    my @reqs = MockUA::requests();
    like(
        $reqs[0]{uri},
        qr{/auth/baz/login$},
        'custom approleMount=baz hits /auth/baz/login'
    );
}

done_testing();
