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

# --- token header sent on every request ---
{
    my $b = MockUA::mockBackend( token => 'abc' );
    MockUA::canned(
        [ 200, { data => { data => { cfgNum => 1 } } } ],
        [ 200, { data => { data => { cfgNum => 2 } } } ],
    );

    $b->load(1);
    $b->load(2);

    my @reqs = MockUA::requests();
    is( scalar @reqs, 2, 'two requests made' );
    for my $i ( 0 .. $#reqs ) {
        is(
            $reqs[$i]{headers}{'X-Vault-Token'},
            'abc',
            "request ${\($i+1)} has X-Vault-Token: abc"
        );
    }
}

# --- X-Vault-Namespace absent when namespace not set ---
{
    my $b = MockUA::mockBackend( token => 'abc' );
    MockUA::canned( [ 200, { data => { data => { cfgNum => 1 } } } ] );

    $b->load(1);

    my $req = MockUA::lastRequest();
    ok( !defined $req->{headers}{'X-Vault-Namespace'},
        'X-Vault-Namespace absent when namespace not set' );
}

# --- X-Vault-Namespace present when namespace set ---
{
    my $b = MockUA::mockBackend( token => 'abc', namespace => 'foo' );
    MockUA::canned( [ 200, { data => { data => { cfgNum => 1 } } } ] );

    $b->load(1);

    my $req = MockUA::lastRequest();
    is(
        $req->{headers}{'X-Vault-Namespace'},
        'foo',
        'X-Vault-Namespace: foo when namespace=foo'
    );
}

done_testing();
