## @file
# JSON file authentication backend
# Development/test only - NOT for production use

## @class
# Authenticate users against a JSON file.
# Inherits from Demo authentication backend.
# JSON file path is read from jsonFileUserPath config parameter
# or LLNG_JSONUSERS environment variable.
package Lemonldap::NG::Portal::Auth::JsonFile;

use strict;
use Mouse;
use JSON;
use Lemonldap::NG::Portal::Main::Constants qw(PE_OK PE_BADCREDENTIALS);

extends 'Lemonldap::NG::Portal::Auth::Demo';

our $VERSION = '0.1.0';

has passwords => ( is => 'rw', default => sub { {} } );

sub init {
    my ($self) = @_;

    my $file = $self->conf->{jsonFileUserPath} || $ENV{LLNG_JSONUSERS};
    unless ($file) {
        $self->logger->error(
            "jsonFileUserPath not set in configuration"
              . " and LLNG_JSONUSERS environment variable is not set" );
        return 0;
    }
    unless ( -r $file ) {
        $self->logger->error("Cannot read JSON users file: $file");
        return 0;
    }

    my $json;
    eval {
        open my $fh, '<', $file or die "Cannot open $file: $!";
        local $/;
        $json = JSON::decode_json(<$fh>);
        close $fh;
    };
    if ($@) {
        $self->logger->error("Failed to load JSON users file: $@");
        return 0;
    }

    # Extract passwords from user entries
    my %passwords;
    if ( $json->{users} ) {
        for my $user ( keys %{ $json->{users} } ) {
            $passwords{$user} = $json->{users}{$user}{password} // $user;
        }
    }
    $self->passwords( \%passwords );

    $self->logger->warn(
        "Using JsonFile authentication backend (development/test only)");

    return $self->Lemonldap::NG::Portal::Auth::_WebForm::init();
}

sub authenticate {
    my ( $self, $req ) = @_;

    my $password = $self->passwords->{ $req->{user} };
    unless ( defined $password && $password eq $req->data->{password} ) {
        $self->userLogger->warn("Bad password for $req->{user}");
        $self->setSecurity($req);
        return PE_BADCREDENTIALS;
    }

    return PE_OK;
}

1;
