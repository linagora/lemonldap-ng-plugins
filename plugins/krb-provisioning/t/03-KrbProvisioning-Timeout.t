use warnings;
use Test::More;
use strict;

require 't/test-lib.pm';

use Lemonldap::NG::Portal::Main::Constants qw(PE_OK);

# Proves the hard timeout: a kadmind/LDAP that never answers must not delay --
# let alone block -- the login. The real _setKerberosPassword (fork + bounded
# waitpid + SIGKILL) is exercised here; only the backend dispatch is stubbed to
# hang, so the parent must give up after krbConnectTimeout and still return
# PE_OK.

my $plugin_class = 'Lemonldap::NG::Portal::Plugins::KrbProvisioning';
our @LOGS;

my $op;
ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel                => 'error',
                logger                  => 't::TestStdLogger',
                domain                  => 'op.com',
                portal                  => 'http://auth.op.com',
                authentication          => 'Demo',
                userDB                  => 'Same',
                customPlugins           => '::Plugins::KrbProvisioning',
                krbProvisioningActivation => 1,
                krbRealm                => 'EXAMPLE.COM',
                krbAdminServer          => 'kdc.example.com',
                krbServicePrincipal     => 'lemonldap/admin@EXAMPLE.COM',
                krbKeytab               => '/nonexistent/krb.keytab',
                krbConnectTimeout       => 1,
            }
        }
    ),
    'Portal initialized with a 1s kadmind timeout'
);

my $plugin = $op->p->loadedModules->{$plugin_class};
ok( $plugin, 'KrbProvisioning plugin is loaded' );
count(1);

# Stub the backend so it hangs far longer than the timeout. The forked child
# runs this (and is SIGKILLed); the real _setKerberosPassword wrapper stays.
{
    no warnings 'redefine', 'once';
    *Lemonldap::NG::Portal::Plugins::KrbProvisioning::_dispatchBackend =
      sub { sleep 30; return 1; };

    # Capture logs to confirm the timeout is reported (without the password).
    *t::TestStdLogger::logprint = sub {
        my ( $level, $message ) = @_;
        push @LOGS, "[$level] $message";
    };
}

# FakeReq mirrors what provision() reads from a real request.
{
    no warnings 'redefine', 'once';
    *FakeReq::data = sub { $_[0]->{_data} };
}
my $req = bless {
    user        => 'dwho',
    sessionInfo => {},
    _data       => { password => 'T0pS3cr3tValue' },
  },
  'FakeReq';

@LOGS = ();
my $t0      = time;
my $rc      = $plugin->provision($req);
my $elapsed = time - $t0;

is( $rc, PE_OK, 'provision returns PE_OK when kadmind never answers' );
cmp_ok( $elapsed, '<', 6,
    "login not blocked: provision returned in ${elapsed}s (timeout 1s)" );
ok( ( grep { /did not respond within/ } @LOGS ),
    'timeout reported in the logs' );
ok( !( grep { /T0pS3cr3tValue/ } @LOGS ),
    'password never appears in the timeout log' );
count(4);

clean_sessions();
done_testing();
