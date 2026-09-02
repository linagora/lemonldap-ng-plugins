##@file
# Register backend creating accounts through an "ldap-rest" service
# (https://github.com/linagora/ldap-rest).
#
# Unlike Password::LdapRest, this backend needs no LDAP connection at all:
# ldap-rest answers both the uniqueness check and the creation.
#
#   GET  <ldapRestUrl>/api/v1/ldap/<ldapRestResource>/<login>  -> 404 = free
#   POST <ldapRestUrl>/api/v1/ldap/<ldapRestResource>
#        { "uid": "...", "cn": "...", "sn": "...", ... }
#
# objectClass and any default attribute are added by ldap-rest itself, from
# the schema of its flat resource.
package Lemonldap::NG::Portal::Register::LdapRest;

use strict;
use Mouse;
use Lemonldap::NG::Portal::Main::Constants;

extends qw(
  Lemonldap::NG::Portal::Lib::LdapRest
  Lemonldap::NG::Portal::Register::Base
);

our $VERSION = '0.1.0';

# Safety net: applyLoginRule() can only build one login, so a directory full
# of homonyms could make computeLogin() loop forever
use constant MAX_LOGIN_TRIES => 100;

# INITIALIZATION

sub init {
    my ($self) = @_;
    return $self->initLdapRest;
}

# RUNNING METHODS

# Compute a free login from register infos
# @result Lemonldap::NG::Portal constant
sub computeLogin {
    my ( $self, $req ) = @_;

    my $login = $self->applyLoginRule($req);
    return PE_MALFORMEDUSER unless $login;

    my $finalLogin = $login;
    my $i          = 0;
    while (1) {
        my $used = $self->isLoginUsed($finalLogin);

        # undef means "ldap-rest did not answer": refuse rather than create
        # an account that may already exist
        return PE_ERROR unless defined $used;
        last unless $used;

        if ( ++$i > MAX_LOGIN_TRIES ) {
            $self->logger->error(
                "Unable to find a free login based on \"$login\"");
            return PE_ERROR;
        }
        $finalLogin = $login . $i;
    }

    $req->data->{registerInfo}->{login} = $finalLogin;
    return PE_OK;
}

## @method int createUser
# Create the entry through ldap-rest
# @result Lemonldap::NG::Portal constant
sub createUser {
    my ( $self, $req ) = @_;
    my $info = $req->data->{registerInfo};

    my $sn = uc $info->{lastname};
    my $gn = ucfirst $info->{firstname};
    my $cn = "$gn $sn";

    my $password = $self->hashPassword( $info->{password} );
    return PE_LDAPERROR unless defined $password;

    my $entry = {
        $self->restMainAttr => $info->{login},
        cn                  => $cn,
        sn                  => $sn,
        givenName           => $gn,
        $self->pwdAttr      => $password,
        mail                => $info->{mail},
    };

    my $res =
      eval { $self->ldapRestCall( 'POST', $self->_collectionPath, $entry ) };
    if ($@) {
        $self->userLogger->error(
            "Can not create entry for " . $info->{login} );
        $self->logger->error("ldap-rest entry creation failed: $@");
        return PE_LDAPERROR;
    }
    unless ( $self->_isSuccess($res) ) {
        $self->userLogger->error(
            "Can not create entry for " . $info->{login} );
        $self->logger->error( 'ldap-rest refused the entry creation: '
              . ( $res->{error} || 'unknown error' ) );
        return PE_LDAPERROR;
    }

    return PE_OK;
}

# PRIVATE METHODS

# Search if login is already in use.
# @return 1 if used, 0 if free, undef if ldap-rest could not be questioned
sub isLoginUsed {
    my ( $self, $login ) = @_;

    my $resp =
      eval { $self->ldapRestRequest( 'GET', $self->_entryPath($login) ) };
    if ( $@ or !$resp ) {
        $self->logger->error(
            "ldap-rest lookup error for $login: " . ( $@ || 'no response' ) );
        return undef;
    }

    if ( $resp->code == 404 ) {
        $self->logger->debug("Login $login is free");
        return 0;
    }
    if ( $resp->is_success ) {
        $self->logger->debug("Login $login already used in LDAP");
        return 1;
    }

    $self->logger->error( "ldap-rest lookup error for $login: "
          . $self->ldapRestError($resp) );
    return undef;
}

1;
