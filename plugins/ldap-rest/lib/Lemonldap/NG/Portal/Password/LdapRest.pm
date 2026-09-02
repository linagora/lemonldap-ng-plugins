##@file
# Password backend that reads the directory directly (LDAP) but delegates
# write operations to an "ldap-rest" service
# (https://github.com/linagora/ldap-rest).
#
# Reads (user lookup, old password verification) still use the LDAP
# connection configured in the "LDAP parameters" section: ldap-rest does not
# provide any "verify this password" endpoint, and a simple bind is the
# canonical way to do it.
#
# Writes go through:
#   PUT <ldapRestUrl>/api/v1/ldap/<ldapRestResource>/<id>
#   { "replace": { "userPassword": "<value>" } }
#
# The call can optionally be authenticated with the "core/auth/token" or
# "core/auth/hmac" plugins of ldap-rest.
package Lemonldap::NG::Portal::Password::LdapRest;

use strict;
use Mouse;
use Lemonldap::NG::Portal::Main::Constants;

extends qw(
  Lemonldap::NG::Portal::Lib::LDAP
  Lemonldap::NG::Portal::Lib::LdapRest
  Lemonldap::NG::Portal::Password::Base
);

our $VERSION = '0.1.0';

# INITIALIZATION

sub init {
    my ($self) = @_;

    return (  $self->initLdapRest
          and $self->Lemonldap::NG::Portal::Password::Base::init
          and $self->Lemonldap::NG::Portal::Lib::LDAP::init );
}

# RUNNING METHODS

# Old password verification is done with a simple bind: ldap-rest has no
# password verification endpoint
sub confirm {
    my ( $self, $req, $pwd, $dn ) = @_;

    # An empty password would trigger an unauthenticated bind, which succeeds
    unless ( defined $pwd and length $pwd ) {
        $self->logger->warn('Empty password given to confirm(), rejecting');
        return 0;
    }

    $dn ||= $req->data->{dn} || $req->sessionInfo->{_dn};
    unless ($dn) {
        $self->logger->error('"dn" is not set, unable to verify password');
        return 0;
    }

    $self->validateLdap;
    unless ( $self->ldap ) {
        $self->logger->error('Unable to connect to LDAP server');
        return 0;
    }

    my $mesg = $self->ldap->bind( $dn, password => $pwd );
    my $res  = ( $mesg and $mesg->code == 0 ) ? 1 : 0;
    $self->userLogger->notice("Bad old password for $dn") unless $res;

    # Restore the manager bind, the connection is shared
    $self->bind;

    return $res;
}

sub modifyPassword {
    my ( $self, $req, $pwd, %args ) = @_;
    my ( $dn, $requireOldPassword );

    # If the password change is done in a different backend,
    # we need to reload the correct DN
    $self->getUser( $req, useMail => $args{useMail} )
      if $self->conf->{ldapGetUserBeforePasswordChange};

    if ( $req->data->{dn} ) {
        $dn = $req->data->{dn};
        $requireOldPassword =
          $self->requireOldPwdRule->( $req, $req->userData );
        $self->logger->debug("Get DN from request data: $dn");
    }
    else {
        $dn = $req->sessionInfo->{_dn};
        $requireOldPassword =
          $self->requireOldPwdRule->( $req, $req->sessionInfo );
        $self->logger->debug("Get DN from session data: $dn");
    }
    unless ($dn) {
        $self->logger->error('"dn" is not set, aborting password modification');
        return PE_ERROR;
    }
    $requireOldPassword = 0 if $args{passwordReset};

    if ($requireOldPassword) {
        return PE_MUST_SUPPLY_OLD_PASSWORD
          unless $req->data->{oldpassword};
        return PE_BADOLDPASSWORD
          unless $self->confirm( $req, $req->data->{oldpassword}, $dn );
    }

    my $value = $self->hashPassword($pwd);
    return PE_ERROR unless defined $value;

    my $id  = $self->_entryId( $req, $dn );
    my $res = eval {
        $self->ldapRestCall(
            'PUT',
            $self->_entryPath($id),
            { replace => { $self->pwdAttr => $value } }
        );
    };
    if ($@) {
        $self->logger->error("ldap-rest password modification failed: $@");
        return PE_ERROR;
    }
    unless ( $self->_isSuccess($res) ) {
        $self->logger->error(
            'ldap-rest refused the password modification: '
              . ( $res->{error} || 'unknown error' ) );
        return PE_ERROR;
    }

    # If password policy and force reset, set reset flag
    if (    $self->conf->{ldapPpolicyControl}
        and $req->data->{forceReset}
        and $self->conf->{ldapUsePasswordResetAttribute} )
    {
        my $attr = $self->conf->{ldapPasswordResetAttribute};
        my $val  = $self->conf->{ldapPasswordResetAttributeValue};
        $res = eval {
            $self->ldapRestCall(
                'PUT',
                $self->_entryPath($id),
                { replace => { $attr => $val } }
            );
        };
        if ($@) {
            $self->logger->error("ldap-rest modify $attr error: $@");
            return PE_LDAPERROR;
        }
        unless ( $self->_isSuccess($res) ) {
            $self->logger->error( "ldap-rest modify $attr error: "
                  . ( $res->{error} || 'unknown error' ) );
            return PE_LDAPERROR;
        }
        $self->logger->debug("$attr set to $val");
    }

    return PE_PASSWORD_OK;
}

# Identifier used in the ldap-rest URL. By default the full DN is used
# (ldap-rest accepts it as long as it is a direct child of its configured
# base and starts with its "mainAttribute"). When "ldapRestIdKey" is set, the
# corresponding session key is used instead (typically "uid").
sub _entryId {
    my ( $self, $req, $dn ) = @_;
    my $key = $self->conf->{ldapRestIdKey};
    return $dn unless $key;

    my $id;
    for my $src ( $req->sessionInfo, $req->userData, $req->data ) {
        next unless ref $src eq 'HASH' and defined $src->{$key};
        $id = $self->p->getFirstValue( $src->{$key} );
        last if ( defined $id and length $id );
    }
    unless ( defined $id and length $id ) {
        $self->logger->warn(
            "Session key \"$key\" is empty, falling back to DN");
        return $dn;
    }
    return $id;
}

1;
