package Lemonldap::NG::Portal::Plugins::OIDCScopeApplications;

# OIDC "applications" scope plugin
#
# Adds an "applications" scope that returns the user's portal application
# list in the userinfo response. This allows OIDC clients to display the
# same application menu as the LLNG portal.
#
# Configuration: enable via oidcRPMetaDataOptionsAllowScopeApplications on
# the target RP.
#
# The scope can be requested by the RP in the authorization request.
# The applications are returned as a JSON-encoded array in the
# "applications" claim of the userinfo response.

use strict;
use Mouse;
use JSON qw(to_json);
use Lemonldap::NG::Portal::Main::Constants qw(PE_OK);

our $VERSION = '2.23.0';

extends 'Lemonldap::NG::Portal::Main::Plugin';

has oidc => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]
          ->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
    }
);

use constant hook => {
    oidcResolveScope             => 'resolveAppScope',
    oidcGenerateUserInfoResponse => 'addApplicationsClaim',
};

sub init {
    my ($self) = @_;
    unless ( $self->conf->{issuerDBOpenIDConnectActivation} ) {
        $self->logger->error(
            'OIDC issuer not enabled, OIDCScopeApplications disabled');
        return 0;
    }
    1;
}

# Hook: oidcResolveScope
# Ensure the "applications" scope is kept if the RP allows it
sub resolveAppScope {
    my ( $self, $req, $scope_values, $rp ) = @_;

    return PE_OK
      unless $self->oidc->rpOptions->{$rp}
      ->{oidcRPMetaDataOptionsAllowScopeApplications};

    # If "applications" was requested but filtered out (oidcServiceAllowOnlyDeclaredScopes),
    # re-add it
    my $requested = $req->param('scope') || '';
    if (    $requested =~ /\bapplications\b/
        and !grep { $_ eq 'applications' } @$scope_values )
    {
        push @$scope_values, 'applications';
        $self->logger->debug(
            "OIDCScopeApplications: re-added 'applications' scope for RP $rp");
    }

    return PE_OK;
}

# Hook: oidcGenerateUserInfoResponse
# Add the applications list to the userinfo response
sub addApplicationsClaim {
    my ( $self, $req, $userinfo_response, $rp, $data ) = @_;

    my $scope = $data->{_scope} || '';
    return PE_OK unless $scope =~ /\bapplications\b/;

    unless ( $self->oidc->rpOptions->{$rp}
        ->{oidcRPMetaDataOptionsAllowScopeApplications} )
    {
        $self->userLogger->info(
            "Attempt to access applications scope without right for RP $rp");
        return PE_OK;
    }

    $self->logger->debug("Building applications list for RP $rp");

    my $basePath = $self->conf->{portal};
    $basePath =~ s#/*$##;
    $basePath .= $self->p->{staticPrefix} . '/common/apps/';

    my @applist = map {
        my @apps = map {
            $_->{applogo} = $basePath . $_->{applogo}
              unless $_->{applogo_icon};
            $_;
        } @{ $_->{applications} };
        $_->{applications};
    } @{ $self->p->menu->appslist($req) };

    $userinfo_response->{applications} = to_json( \@applist );

    return PE_OK;
}

1;
