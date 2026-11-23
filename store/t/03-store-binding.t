#!/usr/bin/perl

# A plugin name published by two configured stores: the first install needs
# --store, an installed plugin stays bound to the store it came from (for
# install, upgrade and check), and only --store moves it.

use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib", "$FindBin::Bin/../lib";

BEGIN { push @INC, "$FindBin::Bin/stub" }

use StoreTest;

plan skip_all => 'gpg not installed' unless have_gpg();

my $env  = new_env();
my $keyA = gen_key( $env, 'storeA' );
my $keyB = gen_key( $env, 'storeB' );

my $urlA = make_store(
    $env, 'storeA',
    key     => $keyA,
    plugins => [
        { name => 'good', version => '1.0', signer => $keyA },
        { name => 'dup',  version => '1.0', signer => $keyA },
    ]
);
my $urlB = make_store(
    $env, 'storeB',
    key     => $keyB,
    plugins => [
        { name => 'good', version => '9.9', signer => $keyB },
        { name => 'dup',  version => '2.0', signer => $keyB },
    ]
);
( my $canonA = $urlA ) =~ s{/+$}{};
( my $canonB = $urlB ) =~ s{/+$}{};

for my $u ( $urlA, $urlB ) {
    my ( $c, $o ) = run_store( $env, {}, 'add-store', $u );
    is( $c, 0, "add-store $u" ) or diag $o;
}

my ( $code, $out ) = run_store( $env, {}, 'install', 'dup' );
isnt( $code, 0, 'name published by two stores: first install refused' );
like( $out, qr/published by several stores/, '... reason' );
like( $out, qr/--store=URL/,                 '... with advice' );
ok( !-e "$env->{autoload}/dup.json", '... nothing installed' );

( $code, $out ) = run_store( $env, {}, 'info', 'dup' );
isnt( $code, 0, 'info refuses to pick a store too' );

( $code, $out ) = run_store( $env, {}, "--store=$urlA", 'install', 'good' );
is( $code, 0, 'install --store picks the store' ) or diag $out;
is( read_state($env)->{installed}{good}{installed_from},
    $canonA, '... recorded (canonical URL)' );

( $code, $out ) = run_store( $env, {}, 'check' );
is( $code, 0, 'check' ) or diag $out;
unlike(
    $out,
    qr/good\s+1\.0 -> 9\.9/,
    'check ignores a higher version from another store'
);
like( $out, qr/up to date/, '... up to date' );

( $code, $out ) = run_store( $env, {}, 'install', 'good' );
is( $code, 0, 'reinstall without --store' ) or diag $out;
like( $out, qr/version 1\.0 from \Q$canonA\E/, '... from the bound store' );
is( read_state($env)->{installed}{good}{version}, '1.0', '... not 9.9' );

( $code, $out ) = run_store( $env, {}, 'install', 'good', '--version=9.9' );
isnt( $code, 0, 'a version only the other store has is refused' );
like( $out, qr/not found: good version 9\.9 in \Q$canonA\E/, '... reason' );

( $code, $out ) = run_store( $env, {}, "--store=$urlB", 'install', 'good' );
is( $code, 0, 'explicit --store moves the plugin' ) or diag $out;
like( $out, qr/switching from store \Q$canonA\E/, '... announced' );
is( read_state($env)->{installed}{good}{installed_from},
    $canonB, '... now bound to the other store' );
is( read_state($env)->{installed}{good}{version}, '9.9', '... its version' );

( $code, $out ) = run_store( $env, {}, 'remove-store', $urlB );
is( $code, 0, 'remove-store (slash form)' ) or diag $out;
ok( !read_state($env)->{stores}{$canonB}, '... pin removed' );

( $code, $out ) = run_store( $env, {}, 'install', 'good' );
isnt( $code, 0, 'bound store no longer configured: refused' );
like( $out, qr/no longer a configured store/, '... reason' );

( $code, $out ) = run_store( $env, {}, 'check' );
like(
    $out,
    qr/good: installed from \Q$canonB\E, which is no longer/,
    'check reports it'
);

done_testing;
