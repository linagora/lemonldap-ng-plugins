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

# --- lock: fresh state (200) → returns 1, POST with cas=0 ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    MockUA::canned( [ 200, { version => 1 } ] );

    my $r = $b->lock;
    is( $r, 1, 'lock returns 1 on fresh 200' );

    my $req  = MockUA::lastRequest();
    my $body = $req->{body};
    is( $body->{options}{cas}, 0, 'lock POST has options.cas=0' );
    ok( defined $body->{data}{pid},       'lock body has pid' );
    ok( defined $body->{data}{expiresAt}, 'lock body has expiresAt' );
    cmp_ok( $body->{data}{expiresAt}, '>', time, 'expiresAt is in the future' );

    is( $req->{method}, 'POST', 'lock uses POST' );
    like(
        $req->{path},
        qr{/secret/data/lmConf/lmConf\.lock$},
        'lock POSTs to lmConf.lock data URL'
    );
}

# --- isLocked: 404 → 0 ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    MockUA::canned( [ 404, undef ] );

    my $r = $b->isLocked;
    is( $r, 0, 'isLocked returns 0 on 404' );
}

# --- isLocked: active lock (expiresAt in future) → 1 ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    my $future = time + 60;
    MockUA::canned(
        [
            200,
            {
                data => {
                    data     => { pid => 12345, expiresAt => $future },
                    metadata => { version => 1 }
                }
            }
        ]
    );

    my $r = $b->isLocked;
    is( $r, 1, 'isLocked returns 1 when expiresAt is in the future' );
}

# --- isLocked: expired lock (expiresAt in past) → 0 (THE critical test) ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    my $past = time - 60;
    MockUA::canned(
        [
            200,
            {
                data => {
                    data     => { pid => 12345, expiresAt => $past },
                    metadata => { version => 1 }
                }
            }
        ]
    );

    my $r = $b->isLocked;
    is( $r, 0, 'isLocked returns 0 when expiresAt is in the past (expired)' );
}

# --- lock: CAS-400 then GET returns 404 (released between POST and GET)
#     → second POST with cas=0 succeeds → return 1, request count == 3 ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    MockUA::canned(
        [ 400, { errors => ['check-and-set parameter did not match'] } ],
        [ 404, undef ],                  # GET returns 404
        [ 200, { version => 1 } ],       # retry POST succeeds
    );

    my $r = $b->lock;
    is( $r, 1, 'lock returns 1 after release-between-POST-and-GET race' );
    is( MockUA::requestCount(), 3, 'exactly 3 requests: POST + GET + retry POST' );

    # Check the retry POST still has cas=0
    my @reqs       = MockUA::requests();
    my $retry_body = $reqs[2]{body};
    is( $retry_body->{options}{cas}, 0, 'retry POST after 404 uses cas=0' );
}

# --- lock: CAS-400 then GET returns held lock (expiresAt > time) → return 0 ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    my $future = time + 60;
    MockUA::canned(
        [ 400, { errors => ['check-and-set parameter did not match'] } ],
        [
            200,
            {
                data => {
                    data     => { pid => 99, expiresAt => $future },
                    metadata => { version => 3 }
                }
            }
        ],
    );

    my $r = $b->lock;
    is( $r, 0, 'lock returns 0 when lock is actively held' );
    like(
        $Lemonldap::NG::Common::Conf::msg,
        qr/Lock held/i,
        'msg contains "Lock held"'
    );
}

# --- lock: CAS-400, GET returns expired lock (version=7)
#     → second POST uses cas=7 → succeeds → return 1 ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    my $past = time - 60;
    MockUA::canned(
        [ 400, { errors => ['check-and-set parameter did not match'] } ],
        [
            200,
            {
                data => {
                    data     => { pid => 77, expiresAt => $past },
                    metadata => { version => 7 }
                }
            }
        ],
        [ 200, { version => 8 } ],    # steal succeeds
    );

    my $r = $b->lock;
    is( $r, 1, 'lock returns 1 after stealing expired lock' );

    # Verify the steal POST used cas=7
    my @reqs        = MockUA::requests();
    my $steal_body  = $reqs[2]{body};
    is( $steal_body->{options}{cas}, 7,
        'steal POST uses cas=7 (fetched version)' );
}

# --- lock: CAS-400, GET expired, steal also fails with 400 → return 0 ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    my $past = time - 60;
    MockUA::canned(
        [ 400, { errors => ['check-and-set parameter did not match'] } ],
        [
            200,
            {
                data => {
                    data     => { pid => 55, expiresAt => $past },
                    metadata => { version => 5 }
                }
            }
        ],
        [ 400, { errors => ['check-and-set parameter did not match'] } ],
    );

    my $r = $b->lock;
    is( $r, 0,
        'lock returns 0 when lock-steal race also fails with 400' );
    like(
        $Lemonldap::NG::Common::Conf::msg,
        qr/Lost lock-steal race/i,
        'msg contains "Lost lock-steal race"'
    );
}

# --- unlock: DELETE to metadata URL, always returns 1 ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    MockUA::canned( [ 204, undef ] );

    my $r = $b->unlock;
    is( $r, 1, 'unlock returns 1 on 204' );

    my $req = MockUA::lastRequest();
    is( $req->{method}, 'DELETE', 'unlock uses DELETE' );
    like(
        $req->{path},
        qr{/secret/metadata/lmConf/lmConf\.lock$},
        'unlock DELETEs metadata/lmConf.lock'
    );
}

# --- unlock: returns 1 even on 500 ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    MockUA::canned(
        [ 500, undef ],
        [ 500, undef ],    # retry
    );

    my $r = $b->unlock;
    is( $r, 1, 'unlock returns 1 even on 500' );
}

done_testing();
