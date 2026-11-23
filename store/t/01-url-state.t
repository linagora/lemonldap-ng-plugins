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

done_testing;
