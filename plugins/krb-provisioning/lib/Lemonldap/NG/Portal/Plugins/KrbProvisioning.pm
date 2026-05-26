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
# Two kadmind backends, by order of preference:
#   1. Authen::Krb5::Admin (libkadm5 bindings) -> in-memory, no shell, no leak.
#   2. Fallback: shell out to `kadmin -k -t <keytab> -p <principal>` feeding the
#      password on STDIN. The password is NEVER passed as an argv argument.
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

# Whether the Authen::Krb5::Admin bindings are available. Resolved lazily and
# only once: if present we use the in-memory API, otherwise we shell to kadmin.
has _krb5AdminAvailable => (
    is      => 'rw',
    lazy    => 1,
    default => sub {
        my ($self) = @_;
        my $ok = eval {
            require Authen::Krb5;
            require Authen::Krb5::Admin;
            1;
        };
        unless ($ok) {
            $self->logger->info( 'KrbProvisioning: Authen::Krb5::Admin not '
                  . 'available, falling back to the kadmin command' );
        }
        return $ok ? 1 : 0;
    },
);

# INITIALIZATION

sub init {
    my ($self) = @_;

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

# RUNNING METHOD (endAuth hook)

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

    # Reject whitespace, NUL, and the principal separators '@' and '/'. Such a
    # login can't map to a single principal component and is almost certainly a
    # spoofed / malformed identity.
    return undef if $login =~ m{[\s\@/\x00]};

    my $fmt = $self->conf->{krbPrincipalFormat} || '%s@%s';
    return sprintf( $fmt, $login, $self->conf->{krbRealm} );
}

# KADMIND BACKEND DISPATCH

sub _setKerberosPassword {
    my ( $self, $princ, $pwd ) = @_;

    if ( $self->_krb5AdminAvailable ) {
        return $self->_setViaKrb5Admin( $princ, $pwd );
    }
    return $self->_setViaShell( $princ, $pwd );
}

# Preferred backend: Authen::Krb5::Admin (libkadm5), entirely in memory.
sub _setViaKrb5Admin {
    my ( $self, $princ, $pwd ) = @_;

    require Authen::Krb5;
    require Authen::Krb5::Admin;
    Authen::Krb5::Admin->import(qw(:constants));

    Authen::Krb5::init_context();

    # Authenticate to kadmind with the service principal via the keytab.
    my $handle = Authen::Krb5::Admin->init_with_skey(
        $self->conf->{krbServicePrincipal},
        $self->conf->{krbKeytab},
        Authen::Krb5::Admin::KADM5_ADMIN_SERVICE(),
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

# Fallback backend: drive the kadmin command, feeding the password on STDIN.
# The password is never present in the argv (cf. /proc/<pid>/cmdline).
sub _setViaShell {
    my ( $self, $princ, $pwd ) = @_;

    # Strip the realm: kadmin commands take the bare principal, the realm is
    # already provided with -r.
    ( my $shortPrinc = $princ ) =~ s/\@.*$//;

    # 1. Existence check (no password involved).
    my ( $exists, undef ) =
      $self->_runKadmin( "getprinc -terse \"$shortPrinc\"", undef );

    # Feed the password twice (kadmin prompts for confirmation), on STDIN only.
    my $stdin = "$pwd\n$pwd\n";

    if ($exists) {
        my ($ok) = $self->_runKadmin( "cpw \"$shortPrinc\"", $stdin );
        die "kadmin cpw returned a non-zero status\n" unless $ok;
        $self->logger->debug("KrbProvisioning: cpw $princ (resync)");
    }
    else {
        my $policy = $self->conf->{krbDefaultPolicy};
        my $query =
          ( defined $policy && length $policy )
          ? "addprinc -policy \"$policy\" \"$shortPrinc\""
          : "addprinc \"$shortPrinc\"";
        my ($ok) = $self->_runKadmin( $query, $stdin );
        die "kadmin addprinc returned a non-zero status\n" unless $ok;
        $self->userLogger->info(
            "KrbProvisioning: created Kerberos principal $princ");
    }

    return 1;
}

# Base kadmin argv, WITHOUT any password. Exposed as a method so the test suite
# can assert the password never appears on the command line.
sub _kadminBaseArgv {
    my ($self) = @_;
    return (
        'kadmin',
        '-k',
        '-t', $self->conf->{krbKeytab},
        '-p', $self->conf->{krbServicePrincipal},
        '-r', $self->conf->{krbRealm},
        '-s', $self->conf->{krbAdminServer},
    );
}

# Run a single kadmin query, optionally feeding $stdin to the child process,
# with a short timeout. Returns (success_bool, captured_output).
sub _runKadmin {
    my ( $self, $query, $stdin ) = @_;

    require IPC::Open3;
    require Symbol;

    my @cmd = ( $self->_kadminBaseArgv, '-q', $query );
    my $timeout = $self->conf->{krbConnectTimeout} || 3;

    my ( $wtr, $rdr, $err );
    $err = Symbol::gensym();

    my $output = '';
    my $pid;
    my $ok = eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm $timeout;

        $pid = IPC::Open3::open3( $wtr, $rdr, $err, @cmd );

        if ( defined $stdin ) {
            print {$wtr} $stdin;
        }
        close $wtr;

        local $/;
        $output = <$rdr> // '';
        $output .= <$err> // '';

        waitpid( $pid, 0 );
        alarm 0;
        1;
    };
    my $error = $@;
    alarm 0;

    if ( !$ok ) {
        # Timeout or spawn failure: reap the child if we have one.
        if ($pid) {
            kill 'TERM', $pid;
            waitpid( $pid, 0 );
        }
        die "kadmin call failed: $error";
    }

    my $status = $?;
    return ( ( $status == 0 ) ? 1 : 0, $output );
}

1;
