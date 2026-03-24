package Lemonldap::NG::Portal::Plugins::OIDCJarmClient;

use strict;
use Mouse;
use Lemonldap::NG::Common::JWT qw(getJWTPayload);
use Lemonldap::NG::Portal::Main::Constants qw(PE_OK PE_ERROR);

extends 'Lemonldap::NG::Portal::Main::Plugin';

our $VERSION = '2.23.0';

use constant hook => {
    oidcGenerateAuthenticationRequest => 'addResponseMode',
    oidcGotAuthenticationResponse     => 'extractJarmResponse',
};

has oidc => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]
          ->p->loadedModules->{'Lemonldap::NG::Portal::Auth::OpenIDConnect'}
          // $_[0]
          ->p->loadedModules->{'Lemonldap::NG::Portal::Lib::OpenIDConnect'};
    }
);

sub init { 1 }

# Hook 1: Add response_mode to authorization request
sub addResponseMode {
    my ( $self, $req, $op, $params ) = @_;

    my $response_mode =
      $self->oidc->opOptions->{$op}->{oidcOPMetaDataOptionsResponseMode};

    if ($response_mode) {
        $params->{response_mode} = $response_mode;
        $self->logger->debug("JARM: Added response_mode=$response_mode for $op");
    }

    return PE_OK;
}

# Hook 2: Extract parameters from JARM JWT response
sub extractJarmResponse {
    my ( $self, $req, $callback_params ) = @_;

    my $jarm_response = $req->param('response');
    return PE_OK unless $jarm_response;

    $self->logger->debug("JARM response detected");

    # Extract state without verification to find the OP
    my $unverified = getJWTPayload($jarm_response);
    unless ($unverified) {
        $self->logger->error("Cannot decode JARM JWT");
        return PE_ERROR;
    }

    my $state = $unverified->{state};
    unless ($state) {
        $self->logger->error("No state in JARM response");
        return PE_ERROR;
    }

    # Restore state to get the OP
    unless ( $self->oidc->extractState( $req, $state ) ) {
        $self->logger->error("Cannot extract state from JARM response");
        return PE_ERROR;
    }

    my $op = $req->data->{_oidcOPCurrent};
    unless ($op) {
        $self->logger->error("OP not found for JARM response");
        return PE_ERROR;
    }

    $self->logger->debug("JARM: Processing response for OP $op");

    # Decrypt if JWE (5 parts)
    my @parts = split /\./, $jarm_response;
    if ( @parts == 5 ) {
        $self->logger->debug("JARM response is encrypted (JWE)");
        $jarm_response = $self->oidc->decryptJwt($jarm_response);
        unless ($jarm_response) {
            $self->logger->error("Failed to decrypt JARM JWE");
            return PE_ERROR;
        }
    }

    # Verify signature
    my $payload = $self->oidc->decodeJWT( $jarm_response, $op );
    unless ($payload) {
        $self->logger->error("JARM signature verification failed");
        return PE_ERROR;
    }

    # Validate issuer
    my $issuer = $self->oidc->opMetadata->{$op}->{conf}->{issuer};
    if ( $payload->{iss} && $issuer && $payload->{iss} ne $issuer ) {
        $self->logger->error(
            "JARM issuer mismatch: got $payload->{iss}, expected $issuer");
        return PE_ERROR;
    }

    # Validate audience
    my $client_id =
      $self->oidc->opOptions->{$op}->{oidcOPMetaDataOptionsClientID};
    my $aud = $payload->{aud};
    $aud = [$aud] unless ref($aud) eq 'ARRAY';
    unless ( grep { $_ eq $client_id } @$aud ) {
        $self->logger->error(
            "JARM audience mismatch: $client_id not in audience");
        return PE_ERROR;
    }

    # Validate expiration
    if ( $payload->{exp} && $payload->{exp} < time ) {
        $self->logger->error("JARM response expired");
        return PE_ERROR;
    }

    # Extract verified parameters
    # Store state as hashref so Auth::OpenIDConnect skips extractState
    # (the token was already consumed above)
    $callback_params->{state} = {
        _oidcOPCurrent => $req->data->{_oidcOPCurrent},
        _oidcNonce     => $req->data->{_oidcNonce},
        urldc          => $req->data->{_url},
    };
    $callback_params->{code}  = $payload->{code} if $payload->{code};
    $callback_params->{error} = $payload->{error} if $payload->{error};
    $callback_params->{error_description} = $payload->{error_description}
      if $payload->{error_description};

    # For implicit/hybrid flows
    $callback_params->{id_token} = $payload->{id_token}
      if $payload->{id_token};
    $callback_params->{access_token} = $payload->{access_token}
      if $payload->{access_token};

    $self->logger->debug("JARM response successfully extracted and verified");
    return PE_OK;
}

1;
