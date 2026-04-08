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
        my $host = URI->new($self->conf->{fixedLogoutRedirection})->host;
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
