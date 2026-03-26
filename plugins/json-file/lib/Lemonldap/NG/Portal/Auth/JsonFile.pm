## @file
# JSON file authentication backend
# Development/test only - NOT for production use

## @class
# Authenticate users against a JSON file.
# Inherits from Demo authentication backend.
#
# Requires UserDB::JsonFile (or userDB = Same) to be configured.
# Passwords are retrieved from the UserDB module at authenticate time.
package Lemonldap::NG::Portal::Auth::JsonFile;

use strict;
use Mouse;
use Lemonldap::NG::Portal::Main::Constants qw(PE_OK PE_BADCREDENTIALS);

extends 'Lemonldap::NG::Portal::Auth::Demo';

our $VERSION = '0.1.0';

sub init {
    my ($self) = @_;

    my $userDB = $self->conf->{userDB};
    unless ( $userDB eq 'JsonFile' || $userDB eq 'Same' ) {
        $self->logger->error(
            "Auth::JsonFile requires userDB to be set to 'JsonFile' or 'Same'"
        );
        return 0;
    }

    $self->logger->warn(
        "Using JsonFile authentication backend (development/test only)");

    return $self->Lemonldap::NG::Portal::Auth::_WebForm::init();
}

sub authenticate {
    my ( $self, $req ) = @_;

    my $userDB = $self->p->_userDB;
    unless ( $userDB && $userDB->isa('Lemonldap::NG::Portal::UserDB::JsonFile') )
    {
        $self->logger->error("Auth::JsonFile: UserDB::JsonFile is not loaded");
        return PE_BADCREDENTIALS;
    }

    my $password = $userDB->passwords->{ $req->{user} };
    unless ( defined $password && $password eq $req->data->{password} ) {
        $self->userLogger->warn("Bad password for $req->{user}");
        $self->setSecurity($req);
        return PE_BADCREDENTIALS;
    }

    return PE_OK;
}

1;
