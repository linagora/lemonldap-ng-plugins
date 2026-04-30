# RFC 9126 - OAuth 2.0 Pushed Authorization Requests (PAR)
#
# This plugin provides a PAR endpoint that allows clients to push
# authorization request parameters directly to the authorization server
# and receive a request_uri in return. The client then uses this
# request_uri in the authorization request instead of sending all parameters.
package Lemonldap::NG::Portal::Plugins::OIDCPushedAuthRequest;

use strict;
use Mouse;
use JSON;
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
  PE_SENDRESPONSE
);

our $VERSION = '2.23.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

use constant hook => {
    oidcGotRequest       => 'resolvePushedRequest',
    oidcGenerateMetadata => 'addParEndpoint',
};

use constant sessionKind => 'OIDCI';

sub init {
    my ($self) = @_;

    return unless $self->SUPER::init;

    # Get the PAR URI from configuration
    my $parUri = $self->conf->{oidcServiceMetaDataPushedAuthURI};
    unless ($parUri) {
        $self->logger->error('PAR URI not configured');
        return 0;
    }

    $self->oidc->can('addRouteFromConf')->(
        $self, 'Unauth', oidcServiceMetaDataPushedAuthURI => 'pushAuthRequest',
    );
    return 1;
}

# Hook: oidcGenerateMetadata
# Add pushed_authorization_request_endpoint to OIDC discovery document
sub addParEndpoint {
    my ( $self, $req, $metadata ) = @_;
    my $issuer = $metadata->{issuer};
    my $path   = $self->path . '/';
    $path = '/' . $path unless $issuer =~ /\/$/;
    $metadata->{pushed_authorization_request_endpoint} =
      $issuer . $path . $self->conf->{oidcServiceMetaDataPushedAuthURI};
    return PE_OK;
}

# Handle POST /oauth2/par
# RFC 9126 Section 2: Pushed Authorization Request Endpoint
sub pushAuthRequest {
    my ( $self, $req ) = @_;

    $self->logger->debug("PAR request received");

    my ( $rp, $auth_method ) =
      $self->oidc->checkEndPointAuthenticationCredentials($req);

    unless ($rp) {
        $self->logger->error("PAR: Client authentication failed");
        return $self->_parError( $req, 'invalid_client',
            'Client authentication failed' );
    }

    $self->logger->debug("PAR: Client authenticated as $rp");

    # Check if PAR is enabled for this RP
    my $parMode = $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsPAR}
      // '';
    unless ( $parMode =~ /^(?:allow|requir)ed$/ ) {
        $self->logger->error("PAR: PAR is not enabled for $rp");
        return $self->_parError( $req, 'invalid_request',
            'PAR is not enabled for this client' );
    }

    # Step 2: Get and validate request parameters
    my %params;
    for my $param (
        qw/response_type scope client_id state redirect_uri nonce
        response_mode display prompt max_age ui_locales id_token_hint
        login_hint acr_values request code_challenge code_challenge_method
        authorization_details/
      )
    {
        if ( defined( my $val = $req->param($param) ) ) {
            $params{$param} = $val;
        }
    }

    # Verify client_id matches authenticated client
    my $client_id =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};
    if ( $params{client_id} && $params{client_id} ne $client_id ) {
        $self->logger->error(
"PAR: client_id mismatch (param: $params{client_id}, auth: $client_id)"
        );
        return $self->_parError( $req, 'invalid_request',
            'client_id does not match authenticated client' );
    }
    $params{client_id} = $client_id;

    # RFC 9126 Section 2.1: redirect_uri is required
    unless ( $params{redirect_uri} ) {
        $self->logger->error("PAR: redirect_uri is required");
        return $self->_parError( $req, 'invalid_request',
            'redirect_uri is required' );
    }

    # RFC 9126 Section 2.1: response_type is required
    unless ( $params{response_type} ) {
        $self->logger->error("PAR: response_type is required");
        return $self->_parError( $req, 'invalid_request',
            'response_type is required' );
    }

    # Step 3: Validate redirect_uri
    if (
        !$self->oidc->_validateRedirectUri(
            $req, $rp, $params{redirect_uri}, "par"
        )
      )
    {
        $self->logger->error(
            "PAR: redirect_uri $params{redirect_uri} not allowed for $rp");
        return $self->_parError( $req, 'invalid_request',
            'redirect_uri is not allowed' );
    }

    # Step 4: Store the PAR session
    my $ttl = $self->conf->{oidcServicePushedAuthExpiration} || 60;

    my $parSession = $self->oidc->getOpenIDConnectSession(
        undef,
        "pushed_auth_request",
        ttl  => $ttl,
        info => {
            _rp => $rp,
            %params,
        }
    );

    unless ($parSession) {
        $self->logger->error("PAR: Failed to create session");
        return $self->_parError( $req, 'server_error',
            'Failed to create PAR session' );
    }

    my $session_id = $parSession->id;
    $self->logger->debug("PAR: Created session $session_id with TTL $ttl");

# Step 5: Return the request_uri
# RFC 9126 Section 2.2: The request_uri MUST use the urn:ietf:params:oauth:request_uri scheme
    my $request_uri = "urn:ietf:params:oauth:request_uri:$session_id";

    my $response = {
        request_uri => $request_uri,
        expires_in  => $ttl,
    };

    $self->logger->debug("PAR: Returning request_uri=$request_uri");

    return $self->p->sendJSONresponse( $req, $response, code => 201 );
}

# Hook: oidcGotRequest
# Resolve PAR request_uri before processing the authorization request
sub resolvePushedRequest {
    my ( $self, $req, $oidc_request ) = @_;

    my $request_uri = $oidc_request->{request_uri};

    # Check if PAR is required for this RP
    if ( my $client_id = $oidc_request->{client_id} ) {
        if ( my $rp = $self->oidc->getRP($client_id) ) {
            my $parMode =
              $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsPAR} // '';
            if ( $parMode eq 'required' && !$request_uri ) {
                $self->logger->error(
                    "PAR is required for $rp but no request_uri provided");
                return PE_ERROR;
            }
        }
    }

    return PE_OK unless $request_uri;

# RFC 9126 Section 2.2: PAR request_uri uses urn:ietf:params:oauth:request_uri scheme
    unless ( $request_uri =~ /^urn:ietf:params:oauth:request_uri:(.+)$/ ) {

        # Not a PAR request_uri, let the normal flow handle it
        return PE_OK;
    }

    my $session_id = $1;
    $self->logger->debug("PAR: Resolving request_uri for session $session_id");

    # Load the PAR session
    my $parSession =
      $self->oidc->getOpenIDConnectSession( $session_id,
        "pushed_auth_request" );

    unless ($parSession) {
        $self->logger->error("PAR: Session $session_id not found or expired");
        return PE_ERROR;
    }

# RFC 9126 Section 3: client_id must match between PAR and authorization request
    my $par_client_id = $parSession->data->{client_id};
    if (   $oidc_request->{client_id}
        && $oidc_request->{client_id} ne $par_client_id )
    {
        $self->logger->error(
"PAR: client_id mismatch (request: $oidc_request->{client_id}, PAR: $par_client_id)"
        );
        return PE_ERROR;
    }

    # RFC 9126 Section 3: Parameters in the PAR response take precedence
    my @par_params = qw/response_type scope client_id state redirect_uri nonce
      response_mode display prompt max_age ui_locales id_token_hint
      login_hint acr_values request code_challenge code_challenge_method
      authorization_details/;

    for my $param (@par_params) {
        if ( defined $parSession->data->{$param} ) {
            $self->logger->debug("PAR: Setting $param from PAR session");
            $oidc_request->{$param} = $parSession->data->{$param};
        }
    }

    # Remove request_uri from oidc_request to prevent OIDC issuer
    # from trying to process it as a regular Request Object URI
    delete $oidc_request->{request_uri};

    # Delete the PAR session (one-time use)
    # RFC 9126 Section 2.2: request_uri is intended for single use
    $parSession->remove;
    $self->logger->debug("PAR: Session $session_id consumed");

    return PE_OK;
}

# Helper: Return PAR error response
# RFC 9126 Section 2.3: Error Response
sub _parError {
    my ( $self, $req, $error, $description ) = @_;

    my $response = {
        error => $error,
        ( $description ? ( error_description => $description ) : () ),
    };

    # RFC 9126: PAR errors return 400 Bad Request (or 401 for invalid_client)
    my $code = $error eq 'invalid_client' ? 401 : 400;

    return $self->p->sendJSONresponse( $req, $response, code => $code );
}

1;
