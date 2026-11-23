#!/usr/bin/perl

# Store URL normalisation (one canonical form for the ini file, the state
# file and every lookup), migration of state files written by older clients,
# and the gpgVerify default.

use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib", "$FindBin::Bin/../lib";

BEGIN { push @INC, "$FindBin::Bin/stub" }

use JSON;
use StoreTest;
use Lemonldap::NG::Common::Store::State;
use Lemonldap::NG::Common::Store::Config;
use Lemonldap::NG::Common::Store::Verify;

my $norm = \&Lemonldap::NG::Common::Store::State::normUrl;
is( $norm->('https://s.test/store/'),    'https://s.test/store', 'slash' );
is( $norm->(' https://s.test/store// '), 'https://s.test/store', 'blanks' );
is( $norm->('https://s.test/store'),     'https://s.test/store', 'unchanged' );

my $env = new_env();

subtest 'state written by an older client is migrated' => sub {
    write_file(
        $env->{state},
        encode_json(
            {
                stores => {
                    'https://a.test/'  => { gpgFingerprint => 'AAAA' },
                    'https://b.test//' => { gpgFingerprint => 'BBB1' },
                    'https://b.test'   => { gpgFingerprint => 'BBB2' },
                },
                installed => {
                    p =>
                      { version => '1.0', installed_from => 'https://a.test/' }
                },
            }
        )
    );
    my $state =
      Lemonldap::NG::Common::Store::State->new( stateFile => $env->{state} );
    is( $state->getStore('https://a.test')->{gpgFingerprint},
        'AAAA', 'pin recorded with a trailing slash found without it' );
    is( $state->getStore('https://a.test/')->{gpgFingerprint},
        'AAAA', '... and with it' );
    is( $state->getStore('https://b.test/')->{gpgFingerprint},
        'BBB2',
        'canonical entry wins on collision (the one older clients read)' );
    is( $state->get('p')->{installed_from},
        'https://a.test', 'installed_from normalised' );

    $state->add( 'q', version => '1', installed_from => 'https://a.test///' );
    my $saved = read_state($env);
    is_deeply(
        [ sort keys %{ $saved->{stores} } ],
        [ 'https://a.test', 'https://b.test' ],
        'migrated keys persisted on next write'
    );
    is( $saved->{installed}{q}{installed_from},
        'https://a.test', 'new installed_from normalised' );

    $state->removeStore('https://a.test/');
    ok( !$state->getStore('https://a.test'), 'removeStore normalises' );
};

subtest 'ini storeUrls are normalised' => sub {
    write_file( $env->{ini},
"[store]\nstoreUrls = https://a.test/, https://a.test, https://b.test//\n"
    );
    local $ENV{LLNG_STORE_URLS};
    delete $ENV{LLNG_STORE_URLS};
    my $config =
      Lemonldap::NG::Common::Store::Config->new( confFile => $env->{ini} );
    is_deeply(
        [ $config->storeUrls ],
        [ 'https://a.test', 'https://b.test' ],
        'deduplicated, canonical'
    );

    my ( $ok, $msg ) = $config->addStore('https://b.test/');
    ok( !$ok, 'adding the same store with a slash is a duplicate' );

    ( $ok, $msg ) = $config->addStore('https://c.test/');
    ok( $ok, 'new store added' );
    is_deeply(
        [ $config->storeUrls ],
        [ 'https://a.test', 'https://b.test', 'https://c.test' ],
        'stored canonical'
    );
    ( $ok, $msg ) = $config->removeStore('https://a.test/');
    ok( $ok, 'remove-store accepts the slash form' );
    is_deeply( [ $config->storeUrls ],
        [ 'https://b.test', 'https://c.test' ], 'removed' );
};

subtest 'gpgVerify defaults to required' => sub {
    write_file( $env->{ini}, "[store]\n" );
    local $ENV{LLNG_STORE_GPGVERIFY};
    delete $ENV{LLNG_STORE_GPGVERIFY};
    my $config =
      Lemonldap::NG::Common::Store::Config->new( confFile => $env->{ini} );
    is( $config->gpgVerify, 'required', 'config default' );
    is( Lemonldap::NG::Common::Store::Verify->new->mode,
        'required', 'verifier default' );
    is(
        Lemonldap::NG::Common::Store::Verify->new( gpgVerify => 'Optionnal' )
          ->mode,
        'required',
        'unknown value fails closed'
    );
    is(
        Lemonldap::NG::Common::Store::Verify->new( gpgVerify => ' Optional ' )
          ->mode,
        'optional',
        'case and blanks ignored'
    );
};

subtest 'per-store file names are unique' => sub {
    my $key = \&Lemonldap::NG::Common::Store::State::urlFileKey;
    my $kr  = sub {
        Lemonldap::NG::Common::Store::Verify->storeKeyring( '/c', @_ );
    };
    like(
        $kr->('https://a/x'),
        qr{^/c/keyrings/https___a_x-[0-9a-f]{12}\.gpg$},
        'readable name followed by a hash'
    );
    isnt( $kr->('https://a/x'), $kr->('https://a_x'),
        'URLs with the same readable name get distinct keyrings' );
    isnt( $key->('https://a/x'), $key->('https://a_x'), '... and cache files' );
    is( $kr->('https://a/x/'), $kr->('https://a/x'), 'trailing slash ignored' );
    is( $key->(' https://a/x// '), $key->('https://a/x'), '... and blanks' );
    my $long = 'https://a/' . ( 'x' x 1000 );
    cmp_ok( length( $key->($long) ), '<=', 213, 'long URL: bounded length' );
    isnt( $key->($long), $key->( $long . 'y' ), '... still unique' );
};

subtest '_run reports a command killed by a signal as a failure' => sub {
    my ( $exit, undef, $err ) =
      Lemonldap::NG::Common::Store::Verify::_run( $^X, '-e',
        'kill 9, $$; sleep 5' );
    is( $exit, 128 + 9, 'non-zero exit' );
    like( $err, qr/killed by signal 9/, '... reported' );
    ($exit) = Lemonldap::NG::Common::Store::Verify::_run( $^X, '-e', 'exit 3' );
    is( $exit, 3, 'exit code kept' );
    ($exit) = Lemonldap::NG::Common::Store::Verify::_run( $^X, '-e', '1' );
    is( $exit, 0, 'success' );
};

done_testing;
