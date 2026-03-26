## @file
# JSON file userDB backend
# Development/test only - NOT for production use

## @class
# Load user attributes and groups from a JSON file.
# Inherits from Demo userDB backend, replacing its accounts and groups
# data with content from the JSON file.
#
# Also stores passwords for use by Auth::JsonFile.
# JSON file path is read from jsonFileUserPath config parameter
# or LLNG_JSONUSERS environment variable.
package Lemonldap::NG::Portal::UserDB::JsonFile;

use strict;
use Mouse;
use JSON;

extends 'Lemonldap::NG::Portal::UserDB::Demo';

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

    # Populate Demo's data structures so inherited methods work as-is
    %Lemonldap::NG::Portal::UserDB::Demo::demoAccounts = ();
    %Lemonldap::NG::Portal::UserDB::Demo::demoGroups   = ();

    my %passwords;
    if ( $json->{users} ) {
        for my $user ( keys %{ $json->{users} } ) {
            $passwords{$user} = $json->{users}{$user}{password} // $user;
            my %attrs = %{ $json->{users}{$user} };
            delete $attrs{password};
            $attrs{uid} //= $user;
            $Lemonldap::NG::Portal::UserDB::Demo::demoAccounts{$user} =
              \%attrs;
        }
    }
    $self->passwords( \%passwords );

    if ( $json->{groups} ) {
        %Lemonldap::NG::Portal::UserDB::Demo::demoGroups =
          %{ $json->{groups} };
    }

    my $count =
      scalar keys %Lemonldap::NG::Portal::UserDB::Demo::demoAccounts;
    $self->logger->info("JsonFile UserDB: loaded $count user(s) from $file");

    return 1;
}

1;
