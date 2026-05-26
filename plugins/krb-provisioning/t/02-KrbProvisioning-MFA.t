use warnings;
use Test::More;
use strict;
use IO::String;

require 't/test-lib.pm';

# This test proves the plugin provisions Kerberos correctly when a second
# factor (MFA) is enabled. The password is only present on the FIRST request
# (credentials), which ends at the 2FA gate; the OTP is submitted in a SECOND
# request that carries no password and only re-runs buildCookie + endAuth.
# Hooking betweenAuthAndData (not endAuth) is what makes this work.
#
# Uses LLNG's bundled external-2F helper scripts (t/sendOTP.pl, t/vrfyOTP.pl),
# which accept user "dwho" and code "123456".

my $plugin_class = 'Lemonldap::NG::Portal::Plugins::KrbProvisioning';
our @CALLS;

my ( $op, $res );

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel                => 'error',
                domain                  => 'op.com',
                portal                  => 'http://auth.op.com',
                authentication          => 'Demo',
                userDB                  => 'Same',
                ext2fActivation         => 1,
                ext2fCodeActivation     => 0,
                ext2FSendCommand        => 't/sendOTP.pl -uid $uid',
                ext2FValidateCommand    => 't/vrfyOTP.pl -uid $uid -code $code',
                customPlugins           => '::Plugins::KrbProvisioning',
                krbProvisioningActivation => 1,
                krbRealm                => 'EXAMPLE.COM',
                krbAdminServer          => 'kdc.example.com',
                krbServicePrincipal     => 'lemonldap/admin@EXAMPLE.COM',
                krbKeytab               => '/nonexistent/krb.keytab',
            }
        }
    ),
    'Portal with KrbProvisioning + external 2F'
);

# Capture provisioning calls instead of talking to a real kadmind (installed
# after init, see 01-KrbProvisioning.t for the rationale).
{
    no warnings 'redefine';
    *Lemonldap::NG::Portal::Plugins::KrbProvisioning::_setKerberosPassword =
      sub {
        my ( $self, $princ, $pwd ) = @_;
        push @CALLS, { princ => $princ, pwd => $pwd };
        return 1;
      };
}

# ===========================================================================
# Step 1: submit credentials -> second factor required (no cookie yet)
# ===========================================================================
@CALLS = ();
my $body = 'user=dwho&password=dwho';
ok(
    $res = $op->_post(
        '/',
        IO::String->new($body),
        length => length($body),
        accept => 'text/html',
    ),
    'Step 1: credentials submitted'
);
count(1);

# The response is the external-2F form: authentication is pending the second
# factor (the user is NOT logged in yet). Extracting it proves that.
my ( $host, $url, $query ) =
  expectForm( $res, undef, '/ext2fcheck?skin=bootstrap', 'token', 'code' );
ok( !getCookies($res)->{lemonldap},
    'No full session cookie yet (2FA pending)' );

# ...but the Kerberos principal was already provisioned, with the password,
# during betweenAuthAndData -- before the 2FA gate.
is( scalar @CALLS, 1, 'Provisioned on the credentials request (before 2FA)' );
is( $CALLS[0]->{princ}, 'dwho@EXAMPLE.COM', 'Correct principal' );
is( $CALLS[0]->{pwd},   'dwho', 'Cleartext password captured before 2FA' );
count(4);

# Fill the OTP and submit.
$query =~ s/code=/code=123456/;

# ===========================================================================
# Step 2: submit the OTP -> authentication completes (cookie issued)
# ===========================================================================
ok(
    $res = $op->_post(
        '/ext2fcheck',
        IO::String->new($query),
        length => length($query),
        accept => 'text/html',
    ),
    'Step 2: OTP submitted'
);
my $id = expectCookie($res);
ok( $id, 'Got a session cookie after 2FA' );

# The OTP request has no password: endAuth must NOT trigger a second (no-op)
# provisioning. Total stays at exactly one.
is( scalar @CALLS, 1, 'No extra provisioning on the OTP request (no password)' );
count(2);

clean_sessions();
done_testing();
