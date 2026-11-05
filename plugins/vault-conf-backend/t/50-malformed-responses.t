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

subtest 'AppRole login answer is not an object' => sub {
    for my $body ( '[]', '1', '"a"', 'true', '{"auth":"a"}',
        '{"auth":[]}', '{"auth":{"client_token":[]}}' )
    {
        $Lemonldap::NG::Common::Conf::msg = '';
        my $b = MockUA::mockBackend(
            token    => undef,
            roleId   => 'r',
            secretId => 's',
        );
        MockUA::canned( [ 200, $body ] );

        my @r;
        my $lived = eval { @r = $b->available; 1 };
        ok( $lived, "$body: available does not die" ) or diag $@;
        is( scalar @r, 0, "$body: available is empty" );
        like(
            $Lemonldap::NG::Common::Conf::msg,
            qr/unexpected response/,
            "$body: message"
        );
        is( MockUA::requestCount(), 1, "$body: only the login was sent" );
    }
};

subtest 'AppRole lease_duration is not a number' => sub {
    for my $lease ( '[]', '{}', '"abc"', -1, 1.5 ) {
        $Lemonldap::NG::Common::Conf::msg = '';
        my $b = MockUA::mockBackend(
            token    => undef,
            roleId   => 'r',
            secretId => 's',
        );
        MockUA::canned( [
                200,
                {
                    auth => {
                        client_token   => 'tok',
                        lease_duration => $lease
                    }
                }
            ],
            [ 200, { data => { data => { cfgNum => 1 } } } ],
        );

        is_deeply(
            $b->load(1),
            { cfgNum => 1 },
            "load works with lease_duration=$lease"
        );
        cmp_ok( $b->{_tokenExp}, '<=', time,
            "invalid lease_duration $lease gives no lease" );
    }
};

subtest 'load answer has the wrong shape' => sub {
    for my $body ( '[]', '1', '"a"', 'true', '{"data":"a"}', '{"data":[]}',
        '{"data":{"data":[]}}', '{"data":{"data":"a"}}',
        '{"data":{"data":true}}' )
    {
        $Lemonldap::NG::Common::Conf::msg = '';
        my $b = MockUA::mockBackend();
        MockUA::canned( [ 200, $body ] );

        my $r;
        my $lived = eval { $r = $b->load(1); 1 };
        ok( $lived, "$body: load does not die" ) or diag $@;
        is( $r, undef, "$body: load returns undef" );
    }
};

subtest 'lock does not steal an unreadable lock' => sub {
    for my $body ( '[]', '1', '"a"', '{"data":"a"}', '{"data":[]}' ) {
        $Lemonldap::NG::Common::Conf::msg = '';
        my $b = MockUA::mockBackend();
        MockUA::canned(
            [ 400, { errors => ['check-and-set parameter did not match'] } ],
            [ 200, $body ],
        );

        my $r;
        my $lived = eval { $r = $b->lock; 1 };
        ok( $lived, "$body: lock does not die" ) or diag $@;
        ok( !$r,    "$body: lock is refused" );
        is( scalar( grep { $_->{method} eq 'POST' } MockUA::requests() ),
            1, "$body: no steal attempt" );
    }
};

subtest 'available answer has the wrong shape' => sub {
    for my $body ( '[]', '1', '"a"', '{"data":"a"}', '{"data":[]}',
        '{"data":{"keys":"a"}}', '{"data":{"keys":{}}}' )
    {
        $Lemonldap::NG::Common::Conf::msg = '';
        my $b = MockUA::mockBackend();
        MockUA::canned( [ 200, $body ] );

        my @r;
        my $lived = eval { @r = $b->available; 1 };
        ok( $lived, "$body: available does not die" ) or diag $@;
        is( scalar @r, 0, "$body: available is empty" );
    }

    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = MockUA::mockBackend();
    MockUA::canned( [
            200,
            {
                data => {
                    keys =>
                      [ undef, 1, [], {}, 'other', 'lmConf-2', 'lmConf-10' ]
                }
            }
        ]
    );
    is_deeply(
        [ $b->available ],
        [ 2, 10 ],
        'only configuration names are kept, sorted as numbers'
    );
};

subtest 'store error body has the wrong shape' => sub {
    for my $body ( '[]', '1', '"a"', '{"errors":"check-and-set"}',
        '{"errors":{}}' )
    {
        $Lemonldap::NG::Common::Conf::msg = '';
        my $b = MockUA::mockBackend();
        MockUA::canned(
            [ 400, $body ],
            [ 204, undef ],    # unlock
        );

        my $r;
        my $lived = eval { $r = $b->store( { cfgNum => 2 } ); 1 };
        ok( $lived, "$body: store does not die" ) or diag $@;
        is( $r, UNKNOWN_ERROR, "$body: store returns UNKNOWN_ERROR" );
        ok( (
                grep {
                         $_->{method} eq 'DELETE'
                      && $_->{path} =~ /lmConf\.lock$/
                } MockUA::requests()
            ),
            "$body: the lock is released"
        );
    }
};

subtest 'cfgNum must be numeric' => sub {
    for my $n ( 'a/b', 'a?b', 'a#b', '../x', '1/b', "1\n", '' ) {
        $Lemonldap::NG::Common::Conf::msg = '';
        my $b = MockUA::mockBackend();
        my $r;
        my $lived = eval { $r = $b->load($n); 1 };
        ok( $lived, "load('$n') does not die" ) or diag $@;
        is( $r,                     undef, "load('$n') returns undef" );
        is( MockUA::requestCount(), 0,     "load('$n') sends nothing" );

        $b     = MockUA::mockBackend();
        $lived = eval {
            $r =
              Lemonldap::NG::Common::Conf::Backends::OpenBAO::delete( $b, $n );
            1;
        };
        ok( $lived, "delete('$n') does not die" ) or diag $@;
        is( $r,                     0, "delete('$n') returns 0" );
        is( MockUA::requestCount(), 0, "delete('$n') sends nothing" );

        $b     = MockUA::mockBackend();
        $lived = eval { $r = $b->store( { cfgNum => $n } ); 1 };
        ok( $lived, "store('$n') does not die" ) or diag $@;
        is( $r,                     UNKNOWN_ERROR, "store('$n') is refused" );
        is( MockUA::requestCount(), 0, "store('$n') sends nothing" );
    }
};

subtest 'isLocked only reports free when the answer proves it' => sub {
    for my $case (
        [ [ 403, '' ],                                                 1 ],
        [ [ 500, '' ],                                                 1 ],
        [ [ 200, '' ],                                                 1 ],
        [ [ 200, '[]' ],                                               1 ],
        [ [ 200, '{"data":{"data":{"expiresAt":"abc"}}}' ],            1 ],
        [ [ 200, '{"data":{"data":{"expiresAt":[1]}}}' ],              1 ],
        [ [ 404, '' ],                                                 0 ],
        [ [ 200, { data => { data => { expiresAt => time - 60 } } } ], 0 ],
        [ [ 200, { data => { data => { expiresAt => time + 60 } } } ], 1 ],
      )
    {
        $Lemonldap::NG::Common::Conf::msg = '';
        my $b = MockUA::mockBackend();
        my @answers =
          $case->[0][0] == 500 ? ( $case->[0], $case->[0] ) : ( $case->[0] );
        MockUA::canned(@answers);

        my $r;
        my $lived = eval { $r = $b->isLocked; 1 };
        ok( $lived, 'isLocked does not die' ) or diag $@;
        is( $r, $case->[1], "isLocked on status $case->[0][0]" );
    }
};

done_testing();
