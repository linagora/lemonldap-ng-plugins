#!/usr/bin/perl

# GPG verification of store archives, end to end through the CLI, with
# throw-away keys and file:// stores:
# - a store added with a trailing slash still pins its key;
# - under the default mode, an archive signed by another key, a bad
#   signature or an unsigned archive is refused, even if the other key is in
#   the default keyrings of gpg and gpgv;
# - "optional" only tolerates a missing signature;
# - a correctly signed archive is installed;
# - `verify` exits non-zero when the signature fails;
# - a store added by an older client (pin under the slash URL, key in the
#   default keyring, no per-store keyring) is migrated;
# - two store URLs with the same readable file name get distinct keyrings.

use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib", "$FindBin::Bin/../lib";

BEGIN { push @INC, "$FindBin::Bin/stub" }

use File::Copy qw(copy);
use JSON;
use POSIX ();
use StoreTest;

plan skip_all => 'gpg not installed' unless have_gpg();

require Lemonldap::NG::Common::Store::Verify;

my $env   = new_env();
my $key   = gen_key( $env, 'storeA' );
my $other = gen_key( $env, 'other' );

my $url = make_store(
    $env, 'storeA',
    key     => $key,
    plugins => [
        { name => 'good',     version => '1.0', signer => $key },
        { name => 'wrongkey', version => '1.0', signer => $other },
        { name => 'badsig',   version => '1.0', signer => $key, tamper => 1 },
        { name => 'unsigned', version => '1.0' },
    ]
);
like( $url, qr{/$}, 'store URL has a trailing slash' );
( my $canon = $url ) =~ s{/+$}{};

# The other key sits in the default keyrings, as an older add-store of
# another store (or a local gpgv setup) would have left it: in gpg's
# (pubring.kbx) and in gpgv's (trustedkeys.kbx). It must not validate
# archives of this store
export_key( $other, "$env->{dir}/other.asc" );
gpg_import( $env->{gnupg}, "$env->{dir}/other.asc" );
gpg_import( $env->{gnupg}, "$env->{dir}/other.asc", 'trustedkeys.kbx' );
ok( -s "$env->{gnupg}/trustedkeys.kbx", 'other key in gpgv default keyring' );
SKIP: {
    my ($gpgv) = grep { -x } map { "$_/gpgv" } split /:/, $ENV{PATH} || '';
    skip 'gpgv not installed', 1 unless $gpgv;

    # Make sure that the refusals below are not vacuous: gpgv on its default
    # keyring does accept the archive signed by the other key
    my $a   = "$env->{dir}/storeA/llng-plugin-wrongkey-1.0.tar.gz";
    my $pid = fork // die "fork: $!";
    if ( $pid == 0 ) {
        $ENV{GNUPGHOME} = $env->{gnupg};
        open STDOUT, '>', '/dev/null';
        open STDERR, '>', '/dev/null';
        { exec $gpgv, "$a.asc", $a }
        POSIX::_exit(127);
    }
    waitpid $pid, 0;
    is( $?, 0, 'gpgv with its default keyring accepts the other key' );
}

my ( $code, $out ) = run_store( $env, {}, 'add-store', $url );
is( $code, 0, 'add-store with trailing slash' ) or diag $out;
like( $out, qr/Imported key: $key->{fpr}/, 'key imported' );
my $state = read_state($env);
is( $state->{stores}{$canon}{gpgFingerprint},
    $key->{fpr}, 'pin recorded under the canonical URL' );
my $keyring =
  Lemonldap::NG::Common::Store::Verify->storeKeyring( $env->{cache}, $canon );
ok( -s $keyring, 'per-store keyring written' );

( $code, $out ) = run_store( $env, {}, 'install', 'wrongkey' );
isnt( $code, 0, 'default mode: archive signed by another key refused' );
like( $out, qr/GPG verification failed/, '... by GPG' );
ok( !-e "$env->{autoload}/wrongkey.json", '... nothing installed' );

( $code, $out ) = run_store( $env, {}, 'install', 'badsig' );
isnt( $code, 0, 'default mode: bad signature refused' );
like( $out, qr/GPG verification failed/, '... by GPG' );
ok( !-e "$env->{autoload}/badsig.json", '... nothing installed' );

( $code, $out ) = run_store( $env, {}, 'install', 'unsigned' );
isnt( $code, 0, 'default mode: unsigned archive refused' );
like( $out, qr/signature required but not available/, '... reason' );

my $optional = { LLNG_STORE_GPGVERIFY => 'optional' };
( $code, $out ) = run_store( $env, $optional, 'install', 'wrongkey' );
isnt( $code, 0, 'optional: archive signed by another key still refused' );
( $code, $out ) = run_store( $env, $optional, 'install', 'badsig' );
isnt( $code, 0, 'optional: bad signature still refused' );
( $code, $out ) = run_store( $env, $optional, 'install', 'unsigned' );
is( $code, 0, 'optional: unsigned archive accepted' ) or diag $out;
like( $out, qr/Warning: no GPG signature/, '... with a warning' );

( $code, $out ) = run_store( $env, {}, 'install', 'good' );
is( $code, 0, 'default mode: archive signed by the store key installed' )
  or diag $out;
like( $out, qr/GPG signature verified \(key $key->{fpr}\)/, '... verified' );
ok( -e "$env->{autoload}/good.json", '... files installed' );
is( read_state($env)->{installed}{good}{installed_from},
    $canon, '... bound to its store' );

subtest 'verify command' => sub {
    my $d = "$env->{dir}/storeA";
    my $w = "$env->{dir}/verify";
    mkdir $w;
    for my $n (qw(good wrongkey badsig unsigned)) {
        my $a = "llng-plugin-$n-1.0.tar.gz";
        copy( "$d/$a",     "$w/$a" ) or die;
        copy( "$d/$a.asc", "$w/$a.asc" ) if -e "$d/$a.asc";
    }
    my ( $c, $o ) =
      run_store( $env, {}, 'verify', "$w/llng-plugin-good-1.0.tar.gz" );
    is( $c, 0, 'good archive: exit 0' ) or diag $o;
    like( $o, qr/GPG signature verified.*store \Q$canon\E/, '... by store' );
    for my $n (qw(wrongkey badsig unsigned)) {
        ( $c, $o ) =
          run_store( $env, {}, 'verify', "$w/llng-plugin-$n-1.0.tar.gz" );
        isnt( $c, 0, "$n: non-zero exit" );
        unlike( $o, qr/Archive valid/, "$n: not reported valid" );
    }
    ( $c, $o ) = run_store( $env, $optional, 'verify',
        "$w/llng-plugin-badsig-1.0.tar.gz" );
    isnt( $c, 0, 'optional: bad signature, non-zero exit' );
};

subtest 'valid signature by a key that is not the pinned one' => sub {
    my $v = Lemonldap::NG::Common::Store::Verify->new(
        gpgKeyring      => $keyring,
        gpgFingerprints => [ $other->{fpr} ],
    );
    my $a = "$env->{dir}/storeA/llng-plugin-good-1.0.tar.gz";
    my ( $ok, $msg ) = $v->verifyGpg( $a, "$a.asc" );
    ok( !$ok, 'refused' );
    like( $msg, qr/not the key recorded/, '... signer compared to the pin' );

    $v = Lemonldap::NG::Common::Store::Verify->new( gpgKeyring => $keyring );
    ( $ok, $msg ) = $v->verifyGpg( $a, "$a.asc" );
    ok( !$ok, 'required: refused when no fingerprint is recorded' );
    like( $msg, qr/no GPG key is recorded/, '... reason' );
};

subtest 'gpg is used with the store keyring only when gpgv is missing' => sub {
    no warnings 'redefine';
    my $orig = \&Lemonldap::NG::Common::Store::Verify::_findBin;
    local *Lemonldap::NG::Common::Store::Verify::_findBin =
      sub { $_[0] eq 'gpgv' ? undef : $orig->(@_) };
    local $ENV{GNUPGHOME} = $env->{gnupg};    # holds the "other" key
    my $v = Lemonldap::NG::Common::Store::Verify->new(
        gpgKeyring      => $keyring,
        gpgFingerprints => [ $key->{fpr} ],
    );
    my $d = "$env->{dir}/storeA";
    my $a = "$d/llng-plugin-good-1.0.tar.gz";
    my ( $ok, $msg ) = $v->verifyGpg( $a, "$a.asc" );
    ok( $ok, 'good signature verified with gpg' ) or diag $msg;
    $a = "$d/llng-plugin-wrongkey-1.0.tar.gz";
    ( $ok, $msg ) = $v->verifyGpg( $a, "$a.asc" );
    ok( !$ok, 'other key (present in the default keyring) refused' );
    $a = "$d/llng-plugin-badsig-1.0.tar.gz";
    ( $ok, $msg ) = $v->verifyGpg( $a, "$a.asc" );
    ok( !$ok, 'bad signature refused' );
};

subtest 'store added by an older client is migrated' => sub {
    my $env2 = new_env();

    # Older layout: ini and state keyed with the slash, key only in the
    # default keyring of the user who ran add-store
    write_file( $env2->{ini}, "[store]\nstoreUrls = $url\n" );
    write_file(
        $env2->{state},
        encode_json(
            { stores => { $url => { gpgFingerprint => $key->{fpr} } } }
        )
    );
    my ( $c, $o ) = run_store( $env2, {}, 'install', 'wrongkey' );
    isnt( $c, 0, 'no key anywhere: refused' );
    like( $o, qr/remove-store URL' then 'add-store URL/, '... with advice' );

    gpg_import( $env2->{gnupg}, "$env->{dir}/storeA/store-key.asc" );
    ( $c, $o ) = run_store( $env2, {}, 'install', 'wrongkey' );
    isnt( $c, 0, 'migrated store: archive signed by another key refused' );
    like( $o, qr/moved to its own keyring/, '... key moved' );
    ( $c, $o ) = run_store( $env2, {}, 'install', 'good' );
    is( $c, 0, 'migrated store: good archive installed' ) or diag $o;
    my $s = read_state($env2);
    is_deeply( [ keys %{ $s->{stores} } ], [$canon], 'state key migrated' );
};

subtest 'stores whose URLs differ only by "/" vs "_" are kept apart' => sub {
    my $env4 = new_env();
    my $u1   = make_store(
        $env4, 'col/x',
        key     => $key,
        plugins => [ { name => 'p1', version => '1.0', signer => $key } ]
    );
    my $u2 = make_store(
        $env4, 'col_x',
        key     => $other,
        plugins => [ { name => 'p2', version => '1.0', signer => $other } ]
    );
    my $kr = sub {
        Lemonldap::NG::Common::Store::Verify->storeKeyring( $env4->{cache},
            @_ );
    };
    isnt( $kr->($u1), $kr->($u2), 'distinct keyrings' );
    for my $u ( $u1, $u2 ) {
        my ( $c, $o ) = run_store( $env4, {}, 'add-store', $u );
        is( $c, 0, "add-store $u" ) or diag $o;
    }
    ok( -s $kr->($u1) && -s $kr->($u2), 'both keyrings written' );
    for my $p (qw(p1 p2)) {
        my ( $c, $o ) = run_store( $env4, {}, 'install', $p );
        is( $c, 0, "$p installed with the key of its own store" ) or diag $o;
    }

    my ( $c, $o ) = run_store( $env4, {}, 'remove-store', $u1 );
    is( $c, 0, 'remove-store of the first one' ) or diag $o;
    ok( !-e $kr->($u1), '... its keyring removed' );
    ok( -s $kr->($u2),  '... the other keyring kept' );
    ( $c, $o ) = run_store( $env4, {}, 'install', 'p2' );
    is( $c, 0, 'the other store still verifies its archives' ) or diag $o;
    like(
        $o,
        qr/GPG signature verified \(key $other->{fpr}\)/,
        '... with its key'
    );
};

subtest 'add-store refuses a store without key under required' => sub {
    my $env3 = new_env();
    my $u    = make_store( $env3, 'nokey',
        plugins => [ { name => 'x', version => '1' } ] );
    my ( $c, $o ) = run_store( $env3, {}, 'add-store', $u );
    isnt( $c, 0, 'refused' );
    like( $o, qr/does not publish a GPG key/, '... reason' );
    ( $c, $o ) = run_store( $env3, {}, 'list' );
    like( $o, qr/No stores configured/, '... not added' );
};

done_testing;
