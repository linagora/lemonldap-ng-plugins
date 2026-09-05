use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use File::Find;
use Digest::SHA qw(sha256_hex);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

# The user_code is a live approval credential for as long as the enrollment is
# pending. It used to be stored in cleartext in BOTH device-authorization
# session records, and logged in cleartext at debug (creation) and info
# (invalid submission) level. Anyone able to read the session store or the
# production logs could approve — or deny — an enrollment in the device's
# place.
#
# It is now never persisted (the lookup session is *keyed* on
# sha256_hex(user_code), which is all the plugin needs) and never logged in
# cleartext. This test pins both, plus the per-session lockout that stops a
# logged-in user from brute-forcing the code space.

# Capturing logger, installed on the plugin instance ($self->logger is rw,
# inherited from Common::Module).
{

    package t::CaptureLogger;
    sub new { return bless { msgs => $_[1] }, $_[0] }

    foreach my $level (qw(error warn notice info debug)) {
        no strict 'refs';
        *{$level} = sub {
            push @{ $_[0]->{msgs} }, "$level|$_[1]";
            return 1;
        };
    }
}

my $debug = 'error';
my @logs;

my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                        => $debug,
            domain                          => 'op.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            customPlugins => '::Plugins::OIDCDeviceAuthorization',
            oidcServiceDeviceAuthorizationExpiration      => 600,
            oidcServiceDeviceAuthorizationPollingInterval => 5,
            oidcServiceDeviceAuthorizationUserCodeLength  => 8,

            # Lockout under test
            oidcServiceDeviceAuthorizationMaxFailures  => 3,
            oidcServiceDeviceAuthorizationLockoutDelay => 300,
            oidcRPMetaDataOptions                      => {
                rp => {
                    oidcRPMetaDataOptionsDisplayName              => "RP",
                    oidcRPMetaDataOptionsIDTokenExpiration        => 3600,
                    oidcRPMetaDataOptionsIDTokenSignAlg           => "RS256",
                    oidcRPMetaDataOptionsClientID                 => "rpid",
                    oidcRPMetaDataOptionsPublic                   => 1,
                    oidcRPMetaDataOptionsUserIDAttr               => "",
                    oidcRPMetaDataOptionsAccessTokenExpiration    => 3600,
                    oidcRPMetaDataOptionsBypassConsent            => 1,
                    oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);

my $plugin = $op->p->loadedModules->{
    'Lemonldap::NG::Portal::Plugins::OIDCDeviceAuthorization'};
ok( $plugin, 'Device authorization plugin loaded' );
count(1);
$plugin->logger( t::CaptureLogger->new( \@logs ) );

# Every file of the session store that mentions $needle
sub storeHits {
    my ($needle) = @_;
    my @hits;
    find(
        {
            no_chdir => 1,
            wanted   => sub {
                return unless -f $_;
                open my $fh, '<', $_ or return;
                local $/;
                my $content = <$fh>;
                close $fh;
                push @hits, $_ if ( defined $content and $content =~ /\Q$needle\E/ );
            }
        },
        $main::tmpDir
    );
    return @hits;
}

sub logsMentioning {
    my ($needle) = @_;
    return grep { /\Q$needle\E/ } @logs;
}

# --- 1. creating a device authorization ------------------------------------

@logs = ();
my $query = buildForm( { client_id => 'rpid', scope => 'openid profile' } );
my $res   = $op->_post(
    "/oauth2/device", IO::String->new($query),
    accept => 'application/json',
    length => length($query)
);
my $payload = expectJSON($res);

my $device_code = $payload->{device_code};
my $user_code   = $payload->{user_code} =~ s/-//gr;
my $hash        = sha256_hex($user_code);
ok( $user_code, "Got user_code" );
count(1);

is( scalar storeHits($user_code),
    0, "Plaintext user_code is nowhere in the session store" );
ok( scalar storeHits($hash) >= 1,
    "The session store keys the lookup on the code digest" );
count(2);

is( scalar logsMentioning($user_code),
    0, "Plaintext user_code was not logged at creation" );
ok( scalar logsMentioning($hash) >= 1, "Its digest was logged instead" );
count(2);

# The device_code is a secret too: only its digest may be stored
is( scalar storeHits($device_code),
    0, "Plaintext device_code is not in the session store" );
count(1);

# --- 2. submitting an invalid code -----------------------------------------

my $id = login( $op, 'french' );

sub submit {
    my ($code) = @_;
    my $r = $op->_get(
        "/device",
        query  => "user_code=$code",
        cookie => "lemonldap=$id",
        accept => 'text/html'
    );
    my ($csrf) =
      $r->[2]->[0] =~ m%<input type="hidden" name="token" value="([\d_]+?)" />%;
    my $q =
      buildForm( { user_code => $code, action => 'approve', token => $csrf } );
    @logs = ();
    return $op->_post(
        "/device", IO::String->new($q),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($q)
    );
}

my $bogus = 'ZZZZZZZZ';
$res = submit($bogus);
expectOK($res);
like( $res->[2]->[0], qr/invalidUserCode/, "Invalid code rejected" );
is( scalar logsMentioning($bogus),
    0, "Submitted code was not logged in cleartext" );
ok( scalar logsMentioning( sha256_hex($bogus) ) >= 1,
    "Its digest was logged instead" );
count(3);

# --- 3. per-session lockout after too many invalid codes -------------------

# One failure already spent above; two more reach the configured maximum of 3
submit('ZZZZZZZY');
$res = submit('ZZZZZZZX');
like( $res->[2]->[0], qr/invalidUserCode/,
    "Third invalid code still answered with the plain error" );
count(1);

$res = submit('ZZZZZZZW');
like( $res->[2]->[0], qr/deviceTooManyAttempts/,
    "Fourth attempt is locked out" );
count(1);

# A valid code is refused too while the lockout holds: this is a session-wide
# brake, not a per-code one
$res = submit($user_code);
like( $res->[2]->[0], qr/deviceTooManyAttempts/,
    "The lockout also covers the valid code" );
count(1);

# ... until the lockout window elapses
Time::Fake->offset("+10m");
$res = submit($user_code);
expectOK($res);
like( $res->[2]->[0], qr/deviceApproved|success/,
    "Approval works again once the lockout window elapsed" );
count(1);

# and a successful submission clears the budget
my $ssoSession = getSession($id)->data;
ok( !$ssoSession->{_deviceAuthFailures},
    "Failure counter reset by a valid submission" );
count(1);

Time::Fake->reset();

# --- 4. nothing leaks once the code has been exchanged ---------------------

$query = buildForm( {
        grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code => $device_code,
        client_id   => 'rpid',
    }
);
$res = $op->_post(
    "/oauth2/token", IO::String->new($query),
    accept => 'application/json',
    length => length($query)
);
$payload = expectJSON($res);
ok( $payload->{access_token}, "Device got its tokens" );
is( scalar storeHits($user_code),
    0, "Still no plaintext user_code in the store after the exchange" );
count(2);

# The lookup session keyed on the digest is gone with the enrollment
is( scalar storeHits($hash), 0, "Lookup session removed with the enrollment" );
count(1);

clean_sessions();
done_testing();
