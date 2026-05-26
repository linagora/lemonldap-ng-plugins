use warnings;
use Test::More;
use strict;
use IO::String;

require 't/test-lib.pm';

use Lemonldap::NG::Portal::Main::Constants qw(PE_OK);

my $plugin_class = 'Lemonldap::NG::Portal::Plugins::KrbProvisioning';

# Capture provisioning calls and emitted logs. The actual overrides are
# installed *after* the portal is initialized (see below): loading the plugin
# .pm recompiles its subs, so an override placed before init() would be
# clobbered.
our @CALLS;
our @LOGS;
our $FAIL = 0;

my ( $op, $res );

# The keytab is never read here (the kadmin backend is mocked); any path does.
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
            }
        }
    ),
    'Portal with KrbProvisioning initialized'
);

my $plugin = $op->p->loadedModules->{$plugin_class};
ok( $plugin, 'KrbProvisioning plugin is loaded' );
count(1);

# ---------------------------------------------------------------------------
# Install overrides now that the plugin and the test logger are loaded.
# Method dispatch is resolved at call time, so these affect every subsequent
# login handled by the in-process portal. A flag lets us simulate a kadmind
# failure to prove the hook stays non-blocking.
# ---------------------------------------------------------------------------
{
    no warnings 'redefine', 'once';
    *Lemonldap::NG::Portal::Plugins::KrbProvisioning::_setKerberosPassword =
      sub {
        my ( $self, $princ, $pwd ) = @_;
        push @CALLS, { princ => $princ, pwd => $pwd };
        die "simulated kadmind failure\n" if $FAIL;
        return 1;
      };

    # Capture every emitted log line so we can assert the password never leaks.
    *t::TestStdLogger::logprint = sub {
        my ( $level, $message ) = @_;
        push @LOGS, "[$level] $message";
    };
}

# ===========================================================================
# 1. Real login (password present) -> principal is provisioned end-to-end
# ===========================================================================
@CALLS = ();
my $id = $op->login('dwho');
ok( $id, 'Login succeeded and returned a session cookie' );
is( scalar @CALLS, 1, 'Exactly one provisioning call on real login' );
is( $CALLS[0]->{princ}, 'dwho@EXAMPLE.COM', 'Principal mapped to <uid>@REALM' );
is( $CALLS[0]->{pwd},   'dwho',             'Cleartext password passed to backend' );
count(4);

# ===========================================================================
# 2. Cookie SSO (no re-auth) -> no kadmin call (silent no-op)
# ===========================================================================
@CALLS = ();
ok(
    $res = $op->_get(
        '/',
        cookie => "lemonldap=$id",
        accept => 'text/html',
    ),
    'GET / with an existing session cookie'
);
is( scalar @CALLS, 0, 'No provisioning on cookie SSO (no cleartext password)' );
count(2);

# ===========================================================================
# 3. kadmind failure -> authentication still succeeds (non-blocking)
# ===========================================================================
{
    @CALLS = ();
    @LOGS  = ();
    local $FAIL = 1;
    my $id2 = $op->login('rtyler');
    ok( $id2, 'Login still succeeds even though kadmind provisioning failed' );
    is( scalar @CALLS, 1, 'Provisioning was attempted' );
    ok( ( grep { /KrbProvisioning: failed to provision/ } @LOGS ),
        'Provisioning failure was logged at error level' );
    count(3);
}

# ===========================================================================
# 4. _principalFor: mapping and rejection of invalid logins
# ===========================================================================
is( $plugin->_principalFor('alice'),
    'alice@EXAMPLE.COM', '_principalFor builds <uid>@REALM' );
is( $plugin->_principalFor(''),       undef, 'empty login rejected' );
is( $plugin->_principalFor('a b'),    undef, 'login with space rejected' );
is( $plugin->_principalFor('a@b'),    undef, 'login with @ rejected' );
is( $plugin->_principalFor('a/b'),    undef, 'login with / rejected' );
count(5);

# ===========================================================================
# 5. provision(): no-op guards via a lightweight fake request
# ===========================================================================
{
    no warnings 'redefine', 'once';
    *FakeReq::data = sub { $_[0]->{_data} };
}

# No cleartext password -> PE_OK, no call (federation / cookie path)
@CALLS = ();
my $req_nopwd = bless { user => 'dwho', sessionInfo => {}, _data => {} },
  'FakeReq';
is( $plugin->provision($req_nopwd), PE_OK, 'provision returns PE_OK with no password' );
is( scalar @CALLS, 0, 'no backend call when password is absent' );
count(2);

# Password present, valid login -> one call
@CALLS = ();
my $req_ok = bless {
    user        => 'dwho',
    sessionInfo => {},
    _data       => { password => 's3cret' },
  },
  'FakeReq';
is( $plugin->provision($req_ok), PE_OK, 'provision returns PE_OK on success' );
is( scalar @CALLS, 1, 'one backend call when password present' );
is( $CALLS[0]->{princ}, 'dwho@EXAMPLE.COM', 'correct principal from fake req' );
count(3);

# Invalid login -> PE_OK, no call
@CALLS = ();
my $req_bad = bless {
    user        => 'evil user',
    sessionInfo => {},
    _data       => { password => 's3cret' },
  },
  'FakeReq';
is( $plugin->provision($req_bad), PE_OK, 'provision returns PE_OK on invalid login' );
is( scalar @CALLS, 0, 'no backend call for an invalid login' );
count(2);

# A distinctive password (which cannot appear in the principal) must never be
# logged, even when provisioning fails and an error line is emitted.
{
    local $FAIL = 1;
    @LOGS = ();
    my $req_secret = bless {
        user        => 'alice',
        sessionInfo => {},
        _data       => { password => 'T0pS3cr3tValue' },
      },
      'FakeReq';
    is( $plugin->provision($req_secret), PE_OK, 'provision PE_OK despite failure' );
    ok( ( grep { /failed to provision principal alice\@EXAMPLE\.COM/ } @LOGS ),
        'error logged with the principal name' );
    ok( !( grep { /T0pS3cr3tValue/ } @LOGS ),
        'password never appears in any log line' );
    count(3);
}

# ===========================================================================
# 6. _kadminBaseArgv: the password is NEVER on the command line
# ===========================================================================
my @argv = $plugin->_kadminBaseArgv;
ok( ( grep { $_ eq '-k' } @argv ), 'kadmin invoked with -k (keytab auth)' );
ok( ( grep { $_ eq 'lemonldap/admin@EXAMPLE.COM' } @argv ),
    'service principal present in argv' );
ok( !( grep { /s3cret|dwho|-pw/ } @argv ),
    'no password and no -pw flag in argv' );
count(3);

clean_sessions();
done_testing();
