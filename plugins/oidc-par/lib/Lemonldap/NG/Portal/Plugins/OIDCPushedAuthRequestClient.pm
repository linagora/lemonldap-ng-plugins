# RFC 9126 - OAuth 2.0 Pushed Authorization Requests (PAR) - Client Support
#
# This plugin allows LemonLDAP::NG acting as an OIDC RP to use PAR when
# authenticating against an external OP that supports it.
# It hooks into the authorization request generation and:
# 1. Pushes the authorization parameters to the OP's PAR endpoint
# 2. Receives a request_uri in return
# 3. Replaces the original parameters with client_id and request_uri
package Lemonldap::NG::Portal::Plugins::OIDCPushedAuthRequestClient;

use strict;
use Mouse;
use JSON;
use MIME::Base64 qw(encode_base64);
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
);

our $VERSION = '2.23.0';

extends 'Lemonldap::NG::Portal::Main::Plugin';

use constant hook => {
    oidcGenerateAuthenticationRequest => 'usePAR',
};

has oidc => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]->p->loadedModules->{'Lemonldap::NG::Portal::Auth::OpenIDConnect'};
    }
);

sub init { 1 }

sub usePAR {
    my ( $self, $req, $op, $params ) = @_;

    unless ( $self->oidc ) {
        $self->logger->error('Authentication is not OIDC, aborting');
        return PE_ERROR;
    }

    # Check if PAR is enabled for this OP
    my $use_par =
      $self->oidc->opOptions->{$op}->{oidcOPMetaDataOptionsUsePAR} // '';
    return PE_OK unless $use_par;

    # Get the PAR endpoint from metadata
    my $par_endpoint =
      $self->oidc->opMetadata->{$op}->{conf}
      ->{pushed_authorization_request_endpoint};

    unless ($par_endpoint) {
        if ( $use_par eq 'required' ) {
            $self->logger->error(
                "PAR required but OP $op has no PAR endpoint");
            return PE_ERROR;
        }
        $self->logger->debug(
            "PAR enabled but OP $op has no PAR endpoint, skipping");
        return PE_OK;
    }

    $self->logger->debug("Using PAR for OP $op");

    # Get authentication method (same as for token endpoint)
    my $auth_method =
         $self->oidc->opOptions->{$op}
      ->{oidcOPMetaDataOptionsTokenEndpointAuthMethod}
      || 'client_secret_post';
    my $client_id =
      $self->oidc->opOptions->{$op}->{oidcOPMetaDataOptionsClientID};
    my $client_secret =
      $self->oidc->opOptions->{$op}->{oidcOPMetaDataOptionsClientSecret};

    # Prepare the PAR request
    my $par_params = {%$params};
    my $response;

    if ( $auth_method eq 'client_secret_basic' ) {

        # Authorization: Basic base64(client_id:client_secret)
        $response = $self->oidc->ua->post(
            $par_endpoint,
            $par_params,
            "Content-Type"  => 'application/x-www-form-urlencoded',
            "Authorization" => "Basic "
              . encode_base64( "$client_id:$client_secret", '' ),
        );
    }
    elsif ( $auth_method eq 'client_secret_post' ) {

        # client_id and client_secret in the body
        $par_params->{client_id}     = $client_id;
        $par_params->{client_secret} = $client_secret;
        $response                    = $self->oidc->ua->post(
            $par_endpoint,
            $par_params,
            "Content-Type" => 'application/x-www-form-urlencoded',
        );
    }
    elsif ( $auth_method =~ /^(?:client_secret|private_key)_jwt$/ ) {

        # JWT Bearer assertion
        my $alg =
          $self->oidc->opOptions->{$op}
          ->{oidcOPMetaDataOptionsTokenEndpointAuthSigAlg};
        if ( !$alg ) {
            $alg = $auth_method eq 'client_secret_jwt' ? 'HS256' : 'RS256';
        }
        my $time = time;
        my $jws  = $self->oidc->createJWTForOP(
            {
                iss => $client_id,
                sub => $client_id,
                aud => $par_endpoint,
                jti => $self->oidc->generateNonce,
                exp => $time + 30,
                iat => $time,
            },
            $alg, $op
        );
        $par_params->{client_id} = $client_id;
        $par_params->{client_assertion_type} =
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        $par_params->{client_assertion} = $jws;
        $response                       = $self->oidc->ua->post(
            $par_endpoint,
            $par_params,
            "Content-Type" => 'application/x-www-form-urlencoded',
        );
    }
    else {
        $self->logger->error("PAR: Unknown auth method $auth_method");
        return PE_ERROR;
    }

    unless ( $response->is_success ) {
        $self->logger->error( "PAR request failed: " . $response->status_line );
        my $error_body = $response->decoded_content;
        $self->logger->debug("PAR error response: $error_body") if $error_body;
        if ( $use_par eq 'required' ) {
            return PE_ERROR;
        }

        # If PAR is just allowed (not required), fall back to normal flow
        $self->logger->info(
            "PAR failed but not required, falling back to normal flow");
        return PE_OK;
    }

    # Parse the JSON response
    my $par_response;
    eval { $par_response = decode_json( $response->decoded_content ); };
    if ($@) {
        $self->logger->error("Failed to parse PAR response: $@");
        return PE_ERROR;
    }

    my $request_uri = $par_response->{request_uri};
    unless ($request_uri) {
        $self->logger->error("No request_uri in PAR response");
        return PE_ERROR;
    }

    $self->logger->debug("PAR successful, request_uri: $request_uri");

    # Replace all parameters with client_id and request_uri
    %$params = (
        client_id   => $client_id,
        request_uri => $request_uri,
    );

    return PE_OK;
}

1;
