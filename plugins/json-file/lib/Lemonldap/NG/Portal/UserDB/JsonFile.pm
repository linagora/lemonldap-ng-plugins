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
use Lemonldap::NG::Portal::Main::Constants qw(PE_OK);

extends 'Lemonldap::NG::Portal::UserDB::Demo';

our $VERSION = '0.1.18';

has passwords => ( is => 'rw', default => sub { {} } );

# Attributes computed by the core, the authentication module or setGroups().
# A user file must not override them.
sub _isReservedAttr {
    my ( $self, $key ) = @_;
    return 1 if $key =~ /^_/;
    return 1
      if $key eq 'groups'
      || $key eq 'hGroups'
      || $key eq 'ipAddr'
      || $key eq 'UA'
      || $key eq 'authenticationLevel';
    return 0;
}

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

    # Validate the document before touching Demo's data structures: a bad
    # file must disable the backend, not leave it half populated.
    unless ( ref $json eq 'HASH' ) {
        $self->logger->error("JSON users file must contain an object: $file");
        return 0;
    }
    if ( exists $json->{users} ) {
        unless ( ref $json->{users} eq 'HASH' ) {
            $self->logger->error(
                "JSON users file: 'users' must be an object: $file");
            return 0;
        }
        for my $user ( keys %{ $json->{users} } ) {
            unless ( ref $json->{users}{$user} eq 'HASH' ) {
                $self->logger->error( "JSON users file: entry '$user' "
                      . "must be an object: $file" );
                return 0;
            }
        }
    }
    if ( exists $json->{groups} ) {
        unless ( ref $json->{groups} eq 'HASH' ) {
            $self->logger->error(
                "JSON users file: 'groups' must be an object: $file");
            return 0;
        }
    }

    # Populate Demo's data structures so inherited methods work as-is
    %Lemonldap::NG::Portal::UserDB::Demo::demoAccounts = ();
    %Lemonldap::NG::Portal::UserDB::Demo::demoGroups   = ();

    my %passwords;
    my %warned;
    if ( $json->{users} ) {
        for my $user ( keys %{ $json->{users} } ) {
            $passwords{$user} = $json->{users}{$user}{password} // $user;
            my %attrs = %{ $json->{users}{$user} };
            delete $attrs{password};
            for my $key ( sort keys %attrs ) {
                if ( $self->_isReservedAttr($key) ) {
                    $self->logger->warn(
                        "JsonFile UserDB: ignoring reserved attribute "
                          . "'$key' for user '$user'" )
                      unless $warned{$key}++;
                }
            }
            $attrs{uid} //= $user;
            $Lemonldap::NG::Portal::UserDB::Demo::demoAccounts{$user} = \%attrs;
        }
    }
    $self->passwords( \%passwords );

    if ( $json->{groups} ) {
        %Lemonldap::NG::Portal::UserDB::Demo::demoGroups = %{ $json->{groups} };
    }

    my $count =
      scalar keys %Lemonldap::NG::Portal::UserDB::Demo::demoAccounts;
    $self->logger->info("JsonFile UserDB: loaded $count user(s) from $file");

    return 1;
}

# Populate session with every attribute defined in the JSON for this user,
# then run the parent's setSessionInfo so that exportedVars / demoExportedVars
# mappings can still rename or shadow individual keys.
sub setSessionInfo {
    my ( $self, $req ) = @_;
    my $user  = $req->user;
    my $attrs = $Lemonldap::NG::Portal::UserDB::Demo::demoAccounts{$user};
    if ($attrs) {
        for my $k ( keys %$attrs ) {
            next if $self->_isReservedAttr($k);
            my $v = $attrs->{$k};
            next unless defined $v;
            $req->sessionInfo->{$k} = $v;
        }
    }
    return $self->SUPER::setSessionInfo($req);
}

1;
