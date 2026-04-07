## @file
# PACC (Provider Automatic Configuration for Clients) plugin
# Implements draft-ietf-mailmaint-pacc for automatic mail client configuration
package Lemonldap::NG::Portal::Plugins::PACC;

use strict;
use Mouse;
use JSON qw(to_json);
use Lemonldap::NG::Portal::Main::Constants
  qw(PE_OK PE_DONE PE_OIDC_SERVICE_NOT_ALLOWED);

our $VERSION = '2.0.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

# INTERFACE
use constant hook => {
    oidcGotRegistrationRequest        => 'checkRegistrationAllowed',
    oidcGenerateRegistrationResponse  => 'adjustRegistrationMetadata',
};

# INITIALIZATION

## @method boolean init()
# Initialize PACC plugin
sub init {
    my ($self) = @_;

    return unless $self->SUPER::init;

    # Register .well-known/pacc.json endpoint
    my @route = ( '.well-known' => { 'pacc.json' => 'paccMetadata' }, ['GET'] );
    $self->addUnauthRoute(@route)->addAuthRoute(@route);
    $self->logger->debug('PACC endpoint registered at /.well-known/pacc.json');

    return 1;
}

# HOOKS

## @method int checkRegistrationAllowed($req, $client_metadata, $state)
# Hook to allow dynamic registration for native clients when globally disabled
# @param $req Lemonldap::NG::Portal::Main::Request object
# @param $client_metadata hashref Client registration metadata
# @return PE_OK or PE_DONE (if allowed) or PE_ERROR (if rejected in strict mode)
sub checkRegistrationAllowed {
    my ( $self, $req, $client_metadata ) = @_;

    # Only handle if native client registration is allowed
    return PE_OK
      unless $self->conf->{paccAllowNativeClientRegistration};

    # Check if all redirect_uris are loopback (native client)
    my $redirect_uris = $client_metadata->{redirect_uris};
    return PE_OK unless $redirect_uris && ref($redirect_uris) eq 'ARRAY';

    my $all_loopback = 1;
    foreach my $uri (@$redirect_uris) {
        unless ( $uri =~
            /^https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/.*)?$/i
          )
        {
            $all_loopback = 0;
            last;
        }
    }

    if ($all_loopback) {
        $self->logger->debug(
"PACC: Allowing registration for native client with loopback redirect_uris"
        );
        return PE_DONE;
    }
    elsif ( $self->conf->{paccStrictNativeClientOnly} ) {

        # Reject if strict mode and not all URIs are loopback
        $self->logger->error(
"PACC: Rejecting registration - not all redirect_uris are loopback (strict mode enabled)"
        );
        return PE_OIDC_SERVICE_NOT_ALLOWED;
    }

    return PE_OK;
}

## @method int adjustRegistrationMetadata($req, $registration_state)
# Hook for OIDC dynamic registration to adjust client metadata
# Support public clients (token_endpoint_auth_method = none)
# @param $req Lemonldap::NG::Portal::Main::Request object
# @param $registration_state hashref State with client_id, client_secret, etc.
# @return PE_OK
sub adjustRegistrationMetadata {
    my ( $self, $req, $registration_state ) = @_;

    my $client_metadata = $registration_state->{client_metadata};
    my $token_endpoint_auth_method =
      $client_metadata->{token_endpoint_auth_method} || 'client_secret_basic';

    # If client requests public client (no secret), honor it
    if ( $token_endpoint_auth_method eq 'none' ) {
        $self->logger->debug(
            "PACC: Registering public client (no client_secret)");
        $registration_state->{client_secret} = undef;

        # Include in registration response
        $registration_state->{response_fields}->{token_endpoint_auth_method} =
          'none';
    }
    else {
        # Confidential client - include auth method in response
        $registration_state->{response_fields}->{token_endpoint_auth_method} =
          $token_endpoint_auth_method;
    }

    return PE_OK;
}

## @method PSGI-JSON-response paccMetadata($req)
# Return PACC metadata in JSON format
# @param $req Lemonldap::NG::Portal::Main::Request object
# @return PSGI response
sub paccMetadata {
    my ( $self, $req ) = @_;

    $self->logger->debug('PACC metadata requested');

    my $servers = $self->_buildServersConfig();

    # Return error if no servers configured
    unless (%$servers) {
        $self->logger->error('PACC is enabled but no servers are configured');
        return $self->p->sendError( $req, 'No mail servers configured', 503 );
    }

    my $metadata = {
        servers => $servers,
        oAuth2  => {
            issuer => $self->conf->{oidcServiceMetaDataIssuer}
              || $self->p->portal
        }
    };

    $self->logger->debug( 'PACC metadata generated with '
          . scalar( keys %$servers )
          . ' server(s)' );

    return $self->p->sendJSONresponse( $req, $metadata );
}

## @method hashref _buildServersConfig()
# Build the servers configuration for PACC
# @return hashref of server configurations
sub _buildServersConfig {
    my ($self) = @_;

    my $servers = {};

    # IMAP configuration
    if ( $self->conf->{paccImapEnabled} && $self->conf->{paccImapHostname} ) {
        my $auth =
          $self->conf->{paccImapAuth} || 'OAuth2 sasl-SCRAM-SHA-256-PLUS';
        my @auth_methods = split( /\s+/, $auth );
        $servers->{imap} = {
            hostname       => $self->conf->{paccImapHostname},
            port           => $self->conf->{paccImapPort} || 993,
            authentication => \@auth_methods
        };
        $self->logger->debug( 'PACC: IMAP server configured: '
              . $self->conf->{paccImapHostname} );
    }

    # SMTP configuration
    if ( $self->conf->{paccSmtpEnabled} && $self->conf->{paccSmtpHostname} ) {
        my $auth         = $self->conf->{paccSmtpAuth} || 'OAuth2';
        my @auth_methods = split( /\s+/, $auth );
        $servers->{smtp} = {
            hostname       => $self->conf->{paccSmtpHostname},
            port           => $self->conf->{paccSmtpPort} || 465,
            authentication => \@auth_methods
        };
        $self->logger->debug( 'PACC: SMTP server configured: '
              . $self->conf->{paccSmtpHostname} );
    }

    # JMAP configuration (optional)
    if ( $self->conf->{paccJmapEnabled} && $self->conf->{paccJmapUrl} ) {
        $servers->{jmap} = {
            url            => $self->conf->{paccJmapUrl},
            authentication => ['OAuth2']
        };
        $self->logger->debug(
            'PACC: JMAP server configured: ' . $self->conf->{paccJmapUrl} );
    }

    # CalDAV configuration (optional)
    if ( $self->conf->{paccCalDavEnabled} && $self->conf->{paccCalDavUrl} ) {
        $servers->{caldav} = {
            url            => $self->conf->{paccCalDavUrl},
            authentication => ['OAuth2']
        };
        $self->logger->debug(
            'PACC: CalDAV server configured: ' . $self->conf->{paccCalDavUrl} );
    }

    # CardDAV configuration (optional)
    if ( $self->conf->{paccCardDavEnabled} && $self->conf->{paccCardDavUrl} ) {
        $servers->{carddav} = {
            url            => $self->conf->{paccCardDavUrl},
            authentication => ['OAuth2']
        };
        $self->logger->debug( 'PACC: CardDAV server configured: '
              . $self->conf->{paccCardDavUrl} );
    }

    return $servers;
}

1;
