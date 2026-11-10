package Lemonldap::NG::Portal::Plugins::OIDCJarm;

use strict;
use Mouse;
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
);

our $VERSION = '2.23.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

use constant hook => {
    oidcGotRequest                    => 'checkJarmRequest',
    oidcGenerateAuthorizationResponse => 'wrapResponseInJwt',
    oidcGenerateMetadata              => 'addJarmMetadata',
};

# Core validates response_mode before the authorization response hook. JARM
# modes are not in its base list, so rewrite them here and keep the original
# for wrapResponseInJwt.
sub checkJarmRequest {
    my ( $self, $req, $oidc_request ) = @_;

    my $jarm_mode = $oidc_request->{response_mode} // '';
    return PE_OK
      unless ( $jarm_mode =~ /\.jwt$/ or $jarm_mode eq 'jwt' );

    my $client_id = $oidc_request->{client_id};
    my $rp = $client_id ? $self->oidc->getRP($client_id) : undef;
    return PE_OK unless $rp;

    my $jarm_setting =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsJarm} // '';
    unless ( $jarm_setting eq 'allowed' or $jarm_setting eq 'required' ) {
        $self->logger->error(
"JARM response_mode $jarm_mode requested but not allowed for RP $rp"
        );
        return PE_ERROR;
    }

    my $base;
    if ( $jarm_mode eq 'jwt' ) {
        $base = ( ( $oidc_request->{response_type} // '' ) eq 'code' )
          ? 'query'
          : 'fragment';
    }
    else {
        $base = $jarm_mode;
        $base =~ s/\.jwt$//;
    }

    $req->data->{jarm_response_mode} = $jarm_mode;
    $oidc_request->{response_mode}   = $base;
    $self->logger->debug(
        "JARM response_mode $jarm_mode rewritten to $base for RP $rp");
    return PE_OK;
}

sub addJarmMetadata {
    my ( $self, $req, $metadata ) = @_;

    # Add JARM response modes
    push @{ $metadata->{response_modes_supported} },
      "query.jwt", "fragment.jwt", "form_post.jwt", "jwt";

    # Add JARM algorithm metadata
    $metadata->{authorization_signing_alg_values_supported} =
      $metadata->{id_token_signing_alg_values_supported};
    $metadata->{authorization_encryption_alg_values_supported} =
      $metadata->{id_token_encryption_alg_values_supported};
    $metadata->{authorization_encryption_enc_values_supported} =
      $metadata->{id_token_encryption_enc_values_supported};

    return PE_OK;
}

sub wrapResponseInJwt {
    my ( $self, $req, $oidc_request, $rp, $response_params ) = @_;

    my $response_mode =
      $req->data->{jarm_response_mode}
      // $oidc_request->{response_mode}
      // '';
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
