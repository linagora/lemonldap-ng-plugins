use strict;
use warnings;
use Test::More;
use lib 't/lib';
use MockUA;

plan skip_all =>
  "LWP::Protocol::PSGI / Plack::Request / JSON required for these tests"
  unless MockUA::deps_ok();

use_ok('Lemonldap::NG::Common::Conf');

use Lemonldap::NG::Common::Conf::Constants;

$Lemonldap::NG::Common::Conf::msg = '';

# --- store: happy path (200) ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    # store also calls unlock on success? No — only on error. Seed one response.
    MockUA::canned( [ 200, { version => 1 } ] );

    my $r = $b->store( { cfgNum => 42, foo => 'bar' } );
    is( $r, 42, 'store returns cfgNum on success' );

    my $req = MockUA::lastRequest();
    is( $req->{method}, 'POST', 'store uses POST' );
    like(
        $req->{path},
        qr{/secret/data/lmConf/lmConf-42$},
        'store POSTs to correct URL'
    );

    my $body = $req->{body};
    is( $body->{options}{cas},  0,     'store body has options.cas=0' );
    is( $body->{data}{cfgNum}, 42,    'store body has data.cfgNum' );
    is( $body->{data}{foo},    'bar', 'store body has data.foo' );
}

# --- store: 403 → UPLOAD_DENIED ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    # 403 from store + DELETE from unlock
    MockUA::canned(
        [ 403, undef ],
        [ 204, undef ],    # unlock DELETE
    );

    my $r = $b->store( { cfgNum => 1 } );
    is( $r, UPLOAD_DENIED, 'store returns UPLOAD_DENIED on 403' );
}

# --- store: 400 with CAS message → CONFIG_WAS_CHANGED ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    MockUA::canned(
        [ 400, { errors => ['check-and-set parameter did not match'] } ],
        [ 204, undef ],    # unlock
    );

    my $r = $b->store( { cfgNum => 2 } );
    is( $r, CONFIG_WAS_CHANGED,
        'store returns CONFIG_WAS_CHANGED on 400 CAS error' );
}

# --- store: 400 with unrelated body → UNKNOWN_ERROR ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    MockUA::canned(
        [ 400, { errors => ['something else entirely'] } ],
        [ 204, undef ],    # unlock
    );

    my $r = $b->store( { cfgNum => 3 } );
    is( $r, UNKNOWN_ERROR, 'store returns UNKNOWN_ERROR on 400 unrelated error' );
}

# --- store: 5xx twice → UNKNOWN_ERROR, request count == 2 ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    MockUA::canned(
        [ 503, undef ],
        [ 503, undef ],
        [ 204, undef ],    # unlock
    );

    my $r = $b->store( { cfgNum => 4 } );
    is( $r, UNKNOWN_ERROR, 'store returns UNKNOWN_ERROR after two 5xx' );
    # First two requests are the POST retries, third is unlock's DELETE
    my $store_reqs =
      grep { $_->{method} eq 'POST' } MockUA::requests();
    is( $store_reqs, 2, 'exactly 2 POST attempts on 5xx' );
}

# --- load: 200 with correct data ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    MockUA::canned(
        [ 200, { data => { data => { cfgNum => 42, foo => 'bar' } } } ] );

    my $r = $b->load(42);
    is_deeply( $r, { cfgNum => 42, foo => 'bar' }, 'load returns correct hash' );

    my $req = MockUA::lastRequest();
    is( $req->{method}, 'GET', 'load uses GET' );
    like(
        $req->{path},
        qr{/secret/data/lmConf/lmConf-42$},
        'load GETs correct URL'
    );
}

# --- load: 404 → undef ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    MockUA::canned( [ 404, undef ] );

    my $r = $b->load(99);
    is( $r, undef, 'load returns undef on 404' );
}

# --- available: returns sorted numeric list ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    MockUA::canned(
        [
            200,
            {
                data => {
                    keys => [
                        'lmConf-3', 'lmConf-1', 'lmConf.lock', 'random',
                        'lmConf-10'
                    ]
                }
            }
        ]
    );

    my @avail = $b->available;
    is_deeply( \@avail, [ 1, 3, 10 ], 'available returns sorted numeric list' );
}

# --- available: 404 → empty list ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    MockUA::canned( [ 404, undef ] );

    my @avail = $b->available;
    is_deeply( \@avail, [], 'available returns empty list on 404' );
}

# --- delete: 204 → 1 ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    # Conf::delete calls available() first (LIST), then the DELETE
    MockUA::canned(
        [ 200, { data => { keys => ['lmConf-5'] } } ],    # available LIST
        [ 204, undef ],                                    # delete DELETE
    );

    my $r = $b->delete(5);
    is( $r, 1, 'delete returns 1 on 204' );

    my $req = MockUA::lastRequest();
    is( $req->{method}, 'DELETE', 'delete uses DELETE' );
    like(
        $req->{path},
        qr{/secret/metadata/lmConf/lmConf-5$},
        'delete DELETEs metadata URL'
    );
}

# --- delete: 403 → 0 ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();

    # Conf::delete calls available() first (LIST), then the DELETE
    MockUA::canned(
        [ 200, { data => { keys => ['lmConf-5'] } } ],    # available LIST
        [ 403, undef ],                                    # delete DELETE → 403
    );

    my $r = $b->delete(5);
    is( $r, 0, 'delete returns 0 on 403' );
}

# Round-trip: the stored config is the one we get back.
# MockUA uses to_json (which escapes non-ASCII as \uXXXX) and the backend uses
# from_json, so wide-char strings survive the round-trip unchanged.
{
    my $backend = MockUA::mockBackend();

    # \x{e9}\x{e0}\x{fc} = é à ü as wide chars; to_json escapes them as
    # \uXXXX and from_json restores identical wide chars.
    my $utf8_val = "\x{e9}\x{e0}\x{fc}";

    MockUA::handler( sub {
        my $preq = shift;
        if ( $preq->method eq 'POST' && $preq->path_info =~ /lmConf-7/ ) {
            return [
                200,
                { data => { version => 1, created_time => 'now' } }
            ];
        }
        if ( $preq->method eq 'GET' && $preq->path_info =~ /lmConf-7/ ) {
            # Return the body LLNG stored, wrapped in KV v2 envelope
            return [
                200,
                {
                    data => {
                        data => {
                            cfgNum        => 7,
                            testKey       => $utf8_val,
                            locationRules => { test => 'accept' },
                        },
                        metadata => { version => 1 },
                    }
                }
            ];
        }
        return [ 500, { errors => ['unexpected request in round-trip'] } ];
    } );

    is $backend->store(
        {
            cfgNum        => 7,
            testKey       => $utf8_val,
            locationRules => { test => 'accept' },
        }
      ),
      7, 'store round-trip returns cfgNum';

    my $loaded = $backend->load(7);
    is_deeply $loaded,
      {
        cfgNum        => 7,
        testKey       => $utf8_val,
        locationRules => { test => 'accept' },
      },
      'loaded config matches stored (including non-ASCII)';
}

done_testing();
