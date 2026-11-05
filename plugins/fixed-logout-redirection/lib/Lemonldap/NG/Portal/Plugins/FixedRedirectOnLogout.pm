package Lemonldap::NG::Portal::Plugins::FixedRedirectOnLogout;

use strict;
use Mouse;
use Lemonldap::NG::Portal::Main::Constants 'PE_OK';
use URI;

our $VERSION = '2.20.0';

extends 'Lemonldap::NG::Portal::Main::Plugin';

use constant beforeLogout => 'run';

sub init {
    my ($self) = @_;
    if ( $self->conf->{fixedLogoutRedirection} ) {
        my $u = URI->new( $self->conf->{fixedLogoutRedirection} );
        unless ( $u->can('host')
            and defined $u->scheme
            and $u->scheme =~ m#^https?$#i
            and $u->host )
        {
            $self->logger->error(
                'fixedLogoutRedirection must be an http(s) URL with a host');
            return 0;
        }
        my $host = $u->host;
        $self->conf->{trustedDomains} .= " $host";
        $self->conf->{trustedDomains} =~ s/^ //;
    }
    return 1;
}

sub run {
    my ( $self, $req ) = @_;
    if ( $self->conf->{fixedLogoutRedirection} ) {
        $self->logger->debug("Force logout redirection");
        $req->mustRedirect(1);
        $req->urldc( $self->conf->{fixedLogoutRedirection} );
    }
    return PE_OK;
}

1;
