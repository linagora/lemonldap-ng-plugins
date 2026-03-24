package Lemonldap::NG::Portal::Plugins::OIDCJarm;

use strict;
use Mouse;
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
);

our $VERSION = '2.23.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

use constant hook => { oidcGenerateAuthorizationResponse => 'wrapResponseInJwt', };

sub wrapResponseInJwt {
    my ( $self, $req, $oidc_request, $rp, $response_params ) = @_;

    my $response_mode = $oidc_request->{response_mode} // '';
    my $jarm_setting =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsJarm} // '';

    # Check if JARM is required but not requested
    if ( $jarm_setting eq 'required' ) {
        unless ( $response_mode =~ /\.jwt$/ or $response_mode eq 'jwt' ) {
            $self->logger->error(
"JARM is required for RP $rp but response_mode is $response_mode"
            );
            return PE_ERROR;
        }
    }

    # Only process JARM response modes
    return PE_OK
      unless ( $response_mode =~ /\.jwt$/ or $response_mode eq 'jwt' );

    # Check if JARM is allowed for this RP
    unless ( $jarm_setting eq 'allowed' or $jarm_setting eq 'required' ) {
        $self->logger->error(
"JARM response_mode $response_mode requested but not allowed for RP $rp"
        );
        return PE_ERROR;
    }

    $self->logger->debug("Processing JARM response for RP $rp");

    # Build the JARM JWT payload
    my $payload = {
        iss => $self->oidc->get_issuer($req),
        aud => $oidc_request->{client_id},
        exp => time + 300,                      # 5 minutes
        %$response_params,
    };

    # Get signing algorithm
    my $alg = $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsJarmSignAlg}
      || 'RS256';

    # Create signed JWT
    my $jwt = $self->oidc->createJWT( $payload, $alg, $rp );

    unless ($jwt) {
        $self->logger->error("Failed to create JARM JWT for RP $rp");
        return PE_ERROR;
    }

    # Encrypt if configured
    my $enc_alg =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsJarmEncKeyMgtAlg};
    if ($enc_alg) {
        my $enc_enc =
          $self->oidc->rpOptions->{$rp}
          ->{oidcRPMetaDataOptionsJarmEncContentEncAlg}
          || 'A256GCM';
        $jwt = $self->oidc->encryptToken( $rp, $jwt, $enc_alg, $enc_enc );
        unless ($jwt) {
            $self->logger->error("Failed to encrypt JARM JWT for RP $rp");
            return PE_ERROR;
        }
    }

    # Replace response params with the single 'response' parameter
    %$response_params = ( response => $jwt );

    # Modify response_mode to use the base mode
    if ( $response_mode eq 'jwt' ) {

        # Auto-select: query for code flow, fragment for implicit/hybrid
        $oidc_request->{response_mode} =
          ( $oidc_request->{response_type} eq 'code' ) ? 'query' : 'fragment';
    }
    else {
        # Remove .jwt suffix
        $oidc_request->{response_mode} =~ s/\.jwt$//;
    }

    $self->logger->debug(
"JARM response prepared, response_mode set to $oidc_request->{response_mode}"
    );

    return PE_OK;
}

1;
