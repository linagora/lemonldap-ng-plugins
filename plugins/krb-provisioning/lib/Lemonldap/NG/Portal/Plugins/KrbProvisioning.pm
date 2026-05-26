# Kerberos on-the-fly provisioning plugin for LemonLDAP::NG
#
# At each *real* login (cleartext password present), this plugin (re)sets the
# Kerberos key of the user equal to the password just validated by the SSO,
# by talking to a kadmind service. This lets a dedicated MIT KDC issue tickets
# (kinit / Kerberos SSO) for users whose identities live in a separate, general
# LDAP directory that the KDC cannot delegate to at kinit time.
#
# It hooks `betweenAuthAndData`, which runs right after `authenticate` succeeds
# and BEFORE the second-factor gate (`secondFactor`) and `endAuth`. This is the
# only stage where success is already guaranteed AND $req->data->{password} is
# still populated: under MFA, the OTP is submitted in a *second* request that
# carries no password and only re-runs `buildCookie`+`endAuth`, so hooking
# `endAuth` would never provision MFA users. It is strictly NON-BLOCKING: any
# provisioning error is logged but never fails the SSO authentication. When
# there is no cleartext password (SSO cookie reuse, SAML/OIDC/SPNEGO
# federation) it is a silent no-op.
#
# kadmind is reached through Authen::Krb5::Admin (libkadm5 bindings): the key is
# set in memory, no shell, no password on any command line. The module is a hard
# requirement (Debian: libauthen-krb5-admin-perl) -- init() refuses to load the
# plugin if it is missing.
#
# See SPEC: docs/llng-kerberos-provisioning-plugin.md (pure-kdc project).

package Lemonldap::NG::Portal::Plugins::KrbProvisioning;

use strict;
use Mouse;
use Lemonldap::NG::Portal::Main::Constants qw(PE_OK);

our $VERSION = '0.1.0';

extends 'Lemonldap::NG::Portal::Main::Plugin';

use constant name => 'KrbProvisioning';

# Hook: executed just after authentication succeeds and before the second
# factor / session finalization. At this stage $req->data->{password} still
# holds the cleartext password for password-based authentication modules, and
# the login is available as $req->{user}. See the file header for why this is
# preferred over endAuth (MFA compatibility).
use constant betweenAuthAndData => 'provision';

# INITIALIZATION

sub init {
    my ($self) = @_;

    # Hard dependency: without Authen::Krb5::Admin the plugin cannot do anything,
    # so refuse to load with a clear message rather than failing silently at
    # every login.
    unless ( eval { require Authen::Krb5; require Authen::Krb5::Admin; 1 } ) {
        $self->logger->error( 'KrbProvisioning requires Authen::Krb5::Admin '
              . '(Debian: libauthen-krb5-admin-perl); plugin disabled' );
        return 0;
    }

    # Required parameters: without them the plugin cannot reach kadmind.
    for my $key (qw(krbRealm krbAdminServer krbServicePrincipal krbKeytab)) {
        unless ( defined $self->conf->{$key} && length $self->conf->{$key} ) {
            $self->logger->error(
                "KrbProvisioning: missing required configuration '$key'");
            return 0;
        }
    }

    # The keytab must be readable by the portal process; warn (don't fail) so
    # that a transient mount issue doesn't disable the whole portal.
    my $keytab = $self->conf->{krbKeytab};
    unless ( -r $keytab ) {
        $self->logger->warn(
            "KrbProvisioning: keytab '$keytab' is not readable by the portal "
              . 'process; provisioning will fail until it is' );
    }

    return 1;
}

# RUNNING METHOD (betweenAuthAndData hook)

sub provision {
    my ( $self, $req ) = @_;

    # Resolve the login used to derive the principal. At this stage (before
    # setSessionInfo) $req->{user} holds the validated login; sessionInfo holds
    # only what the UserDB populated during getUser. If krbPrincipalAttribute
    # is set but not yet available, fall back to the login.
    my $attr = $self->conf->{krbPrincipalAttribute};
    my $login =
      ( defined $attr && length $attr && defined $req->{sessionInfo}->{$attr} )
      ? $req->{sessionInfo}->{$attr}
      : $req->{user};

    # Cleartext password. Absent on cookie SSO / federation (SAML, OIDC,
    # SPNEGO) -> nothing to provision, silent no-op.
    my $pwd = $req->data->{password};
    return PE_OK unless defined $pwd && length $pwd;

    unless ( defined $login && length $login ) {
        $self->logger->debug(
            'KrbProvisioning: no login available, skipping provisioning');
        return PE_OK;
    }

    my $princ = $self->_principalFor($login);
    unless ( defined $princ ) {
        $self->logger->debug( "KrbProvisioning: cannot build a valid Kerberos "
              . "principal from login '$login', skipping" );
        return PE_OK;
    }

    # Provision the key. Errors are logged (never the password) and swallowed:
    # a provisioning failure must NEVER break the SSO authentication.
    eval {
        $self->_setKerberosPassword( $princ, $pwd );
        1;
    } or do {
        my $err = $@ || 'unknown error';
        chomp $err;
        $self->logger->error(
            "KrbProvisioning: failed to provision principal $princ: $err");
    };

    return PE_OK;    # ALWAYS non-blocking
}

# IDENTITY -> PRINCIPAL MAPPING

# Build the Kerberos principal name from a login, or return undef if the login
# is empty or holds characters that are invalid in a principal component.
sub _principalFor {
    my ( $self, $login ) = @_;
    return undef unless defined $login && length $login;

    # Strict allowlist rather than a blocklist: a login becomes a Kerberos
    # principal component. Only accept characters that are unambiguous there --
    # letters, digits, dot, underscore, hyphen, plus a trailing '$' for machine
    # accounts. This rejects whitespace, '@', '/', NUL, quotes, backslashes and
    # any control/metacharacter that has no business in a principal name.
    return undef unless $login =~ /\A[A-Za-z0-9._-]+\$?\z/;

    my $fmt = $self->conf->{krbPrincipalFormat} || '%s@%s';
    return sprintf( $fmt, $login, $self->conf->{krbRealm} );
}

# KADMIND BACKEND DISPATCH

# Run the kadmind operation under a hard time budget so that an unresponsive
# kadmind (or the Kerberos LDAP behind it) can never delay -- let alone block --
# the login. The work runs in a forked child; the parent waits at most
# krbConnectTimeout seconds, then SIGKILLs the child's whole process group.
#
# Why fork rather than a plain alarm(): the preferred Authen::Krb5::Admin
# backend is an XS call into libkadm5; Perl safe-signals cannot interrupt a
# blocking C syscall, so alarm() alone would not unblock a hung RPC. SIGKILL on
# a separate process does. Any failure (timeout, fork error, backend error) is
# thrown and caught by provision(), which always returns PE_OK.
sub _setKerberosPassword {
    my ( $self, $princ, $pwd ) = @_;

    my $timeout = $self->conf->{krbConnectTimeout} || 5;
    require POSIX;

    # Pipe to carry the child's detailed error message back to the parent, so
    # all logging stays in one place.
    pipe( my $rdr, my $wtr ) or die "pipe failed: $!\n";

    my $pid = fork();
    die "fork failed: $!\n" unless defined $pid;

    unless ($pid) {

        # CHILD: isolate in its own session/process group so the parent can
        # reap any kadmin grandchild too. POSIX::_exit avoids running END/DESTROY
        # blocks, which would otherwise disturb the portal's shared resources.
        close $rdr;
        POSIX::setsid();
        my $rc = 0;
        eval {
            $self->_setViaKrb5Admin( $princ, $pwd );
            1;
        } or do {
            my $e = $@ || 'unknown error';
            chomp $e;
            print {$wtr} $e;
            $rc = 1;
        };
        close $wtr;
        POSIX::_exit($rc);
    }

    # PARENT: bound the wait. alarm() interrupts waitpid() (a Perl-level wait),
    # which is enough here because the blocking work lives in the child.
    close $wtr;
    my $childErr = '';
    my $timedOut = 0;
    {
        local $SIG{ALRM} = sub { die "alarm\n" };
        eval {
            alarm $timeout;
            waitpid( $pid, 0 );
            local $/;
            $childErr = <$rdr> // '';    # small message, EOF is immediate
            alarm 0;
            1;
        } or do { $timedOut = 1 };
        alarm 0;
    }
    close $rdr;

    if ($timedOut) {
        kill 'KILL', $pid;     # the child itself...
        kill 'KILL', -$pid;    # ...and any kadmin grandchild in its group
        waitpid( $pid, 0 );
        die "kadmind did not respond within ${timeout}s\n";
    }

    if ( $? != 0 ) {
        die( ( length $childErr ) ? "$childErr\n" : "kadmin failed\n" );
    }
    return 1;
}

# kadmind backend: Authen::Krb5::Admin (libkadm5), entirely in memory.
sub _setViaKrb5Admin {
    my ( $self, $princ, $pwd ) = @_;

    require Authen::Krb5;
    require Authen::Krb5::Admin;
    Authen::Krb5::Admin->import(qw(:constants));

    Authen::Krb5::init_context();

    # Target the configured kadmind explicitly rather than relying on the
    # system krb5.conf / DNS. krbAdminServer is "host[:port]".
    my ( $host, $port ) = split /:/, $self->conf->{krbAdminServer}, 2;
    my $config = Authen::Krb5::Admin::Config->new;
    $config->realm( $self->conf->{krbRealm} );
    $config->admin_server($host) if defined $host && length $host;
    $config->kadmind_port( int $port ) if defined $port && length $port;

    # Authenticate to kadmind with the service principal via the keytab.
    my $handle = Authen::Krb5::Admin->init_with_skey(
        $self->conf->{krbServicePrincipal},
        $self->conf->{krbKeytab},
        Authen::Krb5::Admin::KADM5_ADMIN_SERVICE(),
        $config,
    ) or die "kadm5 init failed: " . Authen::Krb5::Admin::error() . "\n";

    my $kprinc = Authen::Krb5::parse_name($princ)
      or die "cannot parse principal $princ\n";

    if ( $handle->get_principal($kprinc) ) {

        # Principal exists -> resync its key on every login.
        $handle->chpass_principal( $kprinc, $pwd )
          or die "cpw failed: " . Authen::Krb5::Admin::error() . "\n";
        $self->logger->debug("KrbProvisioning: cpw $princ (resync)");
    }
    else {
        # Principal missing -> create it with this password.
        my $pr = Authen::Krb5::Admin::Principal->new;
        $pr->principal($kprinc);
        my $policy = $self->conf->{krbDefaultPolicy};
        if ( defined $policy && length $policy ) {
            $pr->policy($policy);
            $handle->create_principal( $pr, $pwd,
                Authen::Krb5::Admin::KADM5_PRINCIPAL()
                  | Authen::Krb5::Admin::KADM5_POLICY() )
              or die "addprinc failed: "
              . Authen::Krb5::Admin::error() . "\n";
        }
        else {
            $handle->create_principal( $pr, $pwd )
              or die "addprinc failed: "
              . Authen::Krb5::Admin::error() . "\n";
        }
        $self->userLogger->info(
            "KrbProvisioning: created Kerberos principal $princ");
    }

    return 1;
}

1;
