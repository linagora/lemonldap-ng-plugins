use warnings;
use Test::More;
use strict;
use IO::String;

# A password changed on the portal must reach Kerberos at once, through the
# passwordAfterChange hook: a user who signs in by Kerberos SSO never sends a
# password again, so the next-login resync would never come.

BEGIN {
    plan skip_all =>
      'Authen::Krb5::Admin required (Debian: libauthen-krb5-admin-perl)'
      unless eval { require Authen::Krb5::Admin; 1 };
}

require 't/test-lib.pm';

use Lemonldap::NG::Portal::Main::Constants qw(PE_OK);

my $plugin_class = 'Lemonldap::NG::Portal::Plugins::KrbProvisioning';

our @CALLS;
our @LOGS;
our $FAIL = 0;

my ( $op, $res );

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel                  => 'error',
                logger                    => 't::TestStdLogger',
                domain                    => 'op.com',
                portal                    => 'http://auth.op.com',
                authentication            => 'Demo',
                userDB                    => 'Same',
                passwordDB                => 'Demo',
                customPlugins             => '::Plugins::KrbProvisioning',
                krbProvisioningActivation => 1,
                krbRealm                  => 'EXAMPLE.COM',
                krbAdminServer            => 'kdc.example.com',
                krbServicePrincipal       => 'lemonldap/admin@EXAMPLE.COM',
                krbKeytab                 => '/nonexistent/krb.keytab',
            }
        }
    ),
    'Portal with KrbProvisioning and a password module initialized'
);
my $plugin = $op->p->loadedModules->{$plugin_class};
ok( $plugin, 'KrbProvisioning plugin is loaded' );
count(2);

# Installed after init: loading the plugin recompiles its subs.
{
    no warnings 'redefine', 'once';
    *Lemonldap::NG::Portal::Plugins::KrbProvisioning::_setKerberosPassword =
      sub {
        my ( $self, $princ, $pwd ) = @_;
        push @CALLS, { princ => $princ, pwd => $pwd };
        die "simulated kadmind failure\n" if $FAIL;
        return 1;
      };
    *t::TestStdLogger::logprint = sub {
        my ( $level, $message ) = @_;
        push @LOGS, "[$level] $message";
    };
}

sub changePassword {
    my ( $id, $old, $new, $confirm ) = @_;
    my $body = "oldpassword=$old&newpassword=$new&confirmpassword=$confirm";
    return $op->_post(
        '/', IO::String->new($body),
        cookie => "lemonldap=$id",
        accept => 'application/json',
        length => length($body),
    );
}

my $id = $op->login('dwho');
ok( $id, 'dwho is signed in' );
count(1);

# ===========================================================================
# 1. A successful change sets the Kerberos key to the new password
# ===========================================================================
@CALLS = ();
ok( $res = changePassword( $id, 'dwho', 'N3wPassw0rd', 'N3wPassw0rd' ),
    'Change the password in the password tab' );
count(1);
expectOK($res);
is( scalar @CALLS, 1, 'Exactly one provisioning call on a password change' );
is( $CALLS[0]->{princ}, 'dwho@EXAMPLE.COM', 'Principal mapped to <uid>@REALM' );
is( $CALLS[0]->{pwd}, 'N3wPassw0rd', 'The new password is set, not the old one' );
count(3);

# ===========================================================================
# 2. A change that fails before reaching the directory provisions nothing
# ===========================================================================
@CALLS = ();
ok( $res = changePassword( $id, 'dwho', 'One1', 'Other2' ),
    'Change the password with a confirmation that differs' );
count(1);
is( scalar @CALLS, 0, 'No provisioning when the change is refused' );
count(1);

# ===========================================================================
# 3. kadmind failure: the change still succeeds, the password is not logged
# ===========================================================================
{
    local $FAIL = 1;
    @CALLS = ();
    @LOGS  = ();
    ok( $res = changePassword( $id, 'dwho', 'T0pS3cr3tValue', 'T0pS3cr3tValue' ),
        'Change the password while kadmind fails' );
    count(1);
    expectOK($res);
    is( scalar @CALLS, 1, 'Provisioning was attempted' );
    ok( ( grep { /failed to provision principal dwho\@EXAMPLE\.COM/ } @LOGS ),
        'The failure is logged with the principal name' );
    ok( !( grep { /T0pS3cr3tValue/ } @LOGS ),
        'The password appears in no log line' );
    count(3);
}

# ===========================================================================
# 4. provisionAfterChange(): principal attribute and guards
# ===========================================================================
{
    no warnings 'redefine', 'once';
    *FakeReq::userData = sub { $_[0]->{_userData} };
}

@CALLS = ();
my $req = bless { sessionInfo => {}, _userData => { krbName => 'alice' } },
  'FakeReq';
is( $plugin->provisionAfterChange( $req, 'dwho', 's3cret', 'old' ),
    PE_OK, 'provisionAfterChange returns PE_OK' );
is( $CALLS[0]->{princ}, 'dwho@EXAMPLE.COM',
    'Without krbPrincipalAttribute, the login gives the principal' );
count(2);

{
    local $plugin->conf->{krbPrincipalAttribute} = 'krbName';
    @CALLS = ();
    $plugin->provisionAfterChange( $req, 'dwho', 's3cret', 'old' );
    is( $CALLS[0]->{princ}, 'alice@EXAMPLE.COM',
        'krbPrincipalAttribute is read from the signed-in user' );

    @CALLS = ();
    my $during_auth =
      bless { sessionInfo => { krbName => 'bob' }, _userData => {} },
      'FakeReq';
    $plugin->provisionAfterChange( $during_auth, 'dwho', 's3cret', 'old' );
    is( $CALLS[0]->{princ}, 'bob@EXAMPLE.COM',
        'or, during authentication, from what the UserDB has read' );

    @CALLS = ();
    my $none = bless { sessionInfo => {}, _userData => {} }, 'FakeReq';
    $plugin->provisionAfterChange( $none, 'dwho', 's3cret', 'old' );
    is( $CALLS[0]->{princ}, 'dwho@EXAMPLE.COM',
        'and falls back to the login when the attribute is missing' );
    count(3);
}

@CALLS = ();
is( $plugin->provisionAfterChange( $req, 'dwho', '', 'old' ),
    PE_OK, 'An empty password is a no-op' );
is( $plugin->provisionAfterChange( $req, 'evil user', 's3cret', 'old' ),
    PE_OK, 'An invalid login is a no-op' );
is( scalar @CALLS, 0, 'No backend call for either' );
count(3);

clean_sessions();
done_testing();
