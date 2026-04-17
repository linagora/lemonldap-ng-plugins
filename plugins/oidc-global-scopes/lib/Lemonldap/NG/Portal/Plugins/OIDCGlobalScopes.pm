package Lemonldap::NG::Portal::Plugins::OIDCGlobalScopes;

# OIDC Global Scopes plugin
#
# Allows defining extra claims on existing scopes or new scopes with
# associated claims at the global OIDC service level, applying to all
# relying parties.
#
# Configuration:
#   oidcServiceGlobalExtraScopes (keyTextContainer):
#     key   = scope name (existing like "profile" or new like "corporate")
#     value = space-separated list of claim names (must be declared in
#             the RP's exported vars)
#
# Examples:
#   profile   => department employee_id
#   corporate => department manager office_location

use strict;
use Mouse;
use Lemonldap::NG::Portal::Main::Constants qw(PE_OK);

our $VERSION = '0.2.0';

extends 'Lemonldap::NG::Portal::Main::Plugin';

has oidc => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]
          ->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
    }
);

# Parsed global scopes configuration: { scope => [claim1, claim2, ...] }
has globalScopes => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        my $self = shift;
        my $conf = $self->conf->{oidcServiceGlobalExtraScopes} || {};
        my %parsed;
        foreach my $scope ( keys %$conf ) {
            my @claims = grep { length } split( /\s+/, $conf->{$scope} );
            $parsed{$scope} = \@claims if @claims;
        }
        return \%parsed;
    }
);

# Fallback mapping for claims not declared in an RP's Exported Attributes.
# { claim => "sessionAttr" } or { claim => "sessionAttr;type;array" }
has globalClaimMapping => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        my $self = shift;
        my $conf = $self->conf->{oidcServiceGlobalClaimMapping} || {};
        return { map { $_ => $conf->{$_} } grep { length $conf->{$_} }
              keys %$conf };
    }
);

use constant hook => {
    oidcResolveScope             => 'resolveGlobalScopes',
    oidcGenerateUserInfoResponse => 'addGlobalScopeClaims',
};

sub init {
    my ($self) = @_;
    unless ( $self->conf->{issuerDBOpenIDConnectActivation} ) {
        $self->logger->error(
            'OIDC issuer not enabled, OIDCGlobalScopes disabled');
        return 0;
    }
    my $count = scalar keys %{ $self->globalScopes };
    $self->logger->info(
        "OIDCGlobalScopes: $count global scope(s) configured");
    foreach my $scope ( sort keys %{ $self->globalScopes } ) {
        $self->logger->debug( "OIDCGlobalScopes: scope '$scope' => "
              . join( ' ', @{ $self->globalScopes->{$scope} } ) );
    }
    return 1;
}

# Hook: oidcResolveScope
# Ensure globally-defined scopes are preserved even when
# oidcServiceAllowOnlyDeclaredScopes is enabled
sub resolveGlobalScopes {
    my ( $self, $req, $scope_values, $rp ) = @_;

    my $requested = $req->param('scope') || '';
    my %granted = map { $_ => 1 } @$scope_values;

    foreach my $scope ( keys %{ $self->globalScopes } ) {

        # Only re-add scopes that were actually requested by the RP
        # but got filtered out by oidcServiceAllowOnlyDeclaredScopes
        if ( $requested =~ /\b\Q$scope\E\b/ && !$granted{$scope} ) {
            push @$scope_values, $scope;
            $self->logger->debug(
                "OIDCGlobalScopes: re-added global scope '$scope' for RP $rp");
        }
    }

    return PE_OK;
}

# Hook: oidcGenerateUserInfoResponse
# Add claims defined in global scopes to the userinfo response (fires for
# the /oauth2/userinfo endpoint AND when the ID-token embeds user claims,
# since _generateIDToken calls buildUserInfoResponseFromData).
sub addGlobalScopeClaims {
    my ( $self, $req, $userinfo_response, $rp, $data ) = @_;

    my $scope = $data->{_scope} || '';
    my %granted_scopes = map { $_ => 1 } split( /\s+/, $scope );

    foreach my $scope_name ( keys %{ $self->globalScopes } ) {
        next unless $granted_scopes{$scope_name};

        $self->logger->debug(
            "OIDCGlobalScopes: processing global claims for scope '$scope_name' (RP $rp)"
        );

        foreach my $claim ( @{ $self->globalScopes->{$scope_name} } ) {

            # Skip if the claim was already set (by core or per-RP config)
            next if exists $userinfo_response->{$claim};

            # Fallback: if the RP hasn't declared the claim in its
            # Exported Attributes, lazily inject a mapping so
            # _addAttributeToResponse (and the whole _formatValue /
            # COMPLEX_CLAIM / rpMacros pipeline) works normally.
            # Lookup order: per-RP declaration > global mapping > identity.
            my $rpAttrs = $self->oidc->rpAttributes->{$rp} ||= {};
            unless ( defined $rpAttrs->{$claim} && length $rpAttrs->{$claim} )
            {
                my $mapping = $self->globalClaimMapping->{$claim} // $claim;
                $rpAttrs->{$claim} = $mapping;
                $self->logger->debug(
                    "OIDCGlobalScopes: injected fallback mapping "
                      . "$claim => $mapping for RP $rp" );
            }

            $self->oidc->_addAttributeToResponse( $req, $data,
                $userinfo_response, $rp, $claim );
        }
    }

    return PE_OK;
}

1;
