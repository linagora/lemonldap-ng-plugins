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
    # re-add it. Compare whole scope tokens: "my-applications" is another
    # scope and must not bring "applications" back. The request parameter is
    # not authoritative: PAR, a signed request object or a bounded flow can
    # narrow the scope, and a per-RP rule already decided.
    my $oidc_request = $req->data->{_oidc_request};
    my $requested =
         $req->data->{_oidc_effective_scope}
      // ( ref $oidc_request eq 'HASH' ? $oidc_request->{scope} : undef )
      // $req->param('scope')
      // '';
    my %requested =
      map { $_ => 1 } grep { length } split /\s+/, $requested;
    my $rules = $self->oidc->rpScopeRules->{$rp} || {};
    if ( $requested{applications}
        and !grep { $_ eq 'applications' } @$scope_values
        and !$rules->{applications} )
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
    my %granted =
      map { $_ => 1 } grep { length } split /\s+/, $scope;
    return PE_OK unless $granted{applications};

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

    # The display rules must be evaluated on the token's user, not on the
    # request user: userinfo may be called with no cookie, or with another
    # user's SSO cookie.
    my $userData = ref $data eq 'HASH' ? $data : {};
    my $menu = do {
        local $req->{userData} = $userData;
        $self->p->menu->appslist($req);
    };

    my @applist = map {
        my @apps = map {
            $_->{applogo} = $basePath . $_->{applogo}
              unless $_->{applogo_icon};
            $_;
        } @{ $_->{applications} };
        $_->{applications};
    } @$menu;

    $userinfo_response->{applications} = to_json( \@applist );

    return PE_OK;
}

1;
