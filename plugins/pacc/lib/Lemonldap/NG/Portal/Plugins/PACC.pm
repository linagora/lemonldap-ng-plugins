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
    oidcGotRegistrationRequest => 'checkRegistrationAllowed',
    oidcValidateRedirectUri    => 'allowAnyLoopbackPort',
};

# Loopback redirect URI, split into scheme, host, port and path (with query)
my $LOOPBACK_URI =
  qr{\A(https?)://(localhost|127\.0\.0\.1|\[::1\])(?::(\d{1,5}))?(/\S*)?\z}i;

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
# Hook filtering dynamic registration for PACC native clients
# @param $req Lemonldap::NG::Portal::Main::Request object
# @param $client_metadata hashref Client registration metadata
# @return PE_OK (allowed) or a non-OK constant (rejected)
sub checkRegistrationAllowed {
    my ( $self, $req, $client_metadata ) = @_;

    # Check if all redirect_uris are loopback (native client). An empty list
    # is not a native client, and a URI containing whitespace would be split
    # into several redirect URIs by the core.
    my $redirect_uris = $client_metadata->{redirect_uris};
    return PE_OK unless $redirect_uris && ref($redirect_uris) eq 'ARRAY';

    my $loopback =
      qr{\Ahttps?://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:/\S*)?\z}i;
    my $all_loopback = @$redirect_uris ? 1 : 0;
    foreach my $uri (@$redirect_uris) {
        unless ( defined $uri && !ref $uri && $uri =~ $loopback ) {
            $all_loopback = 0;
            last;
        }
    }

    if ($all_loopback) {
        if ( $self->conf->{paccAllowNativeClientRegistration} ) {
            return PE_OIDC_SERVICE_NOT_ALLOWED
              if $self->conf->{paccStrictNativeClientOnly}
              and !$self->_checkNativeMetadata($client_metadata);
            $self->logger->debug(
"PACC: Allowing registration for native client with loopback redirect_uris"
            );
            return PE_OK;
        }
        $self->logger->error(
"PACC: Rejecting loopback client registration (native clients disabled)"
        );
        return PE_OIDC_SERVICE_NOT_ALLOWED;
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

## @method boolean _checkNativeMetadata($client_metadata)
# Strict mode: refuse the client metadata that a native app does not need
# and that make the portal request a URL or insert it in a page. The portal
# requests request_uris, jwks_uri and backchannel_logout_uri itself, so an
# anonymous client could make it reach internal hosts; frontchannel_logout_uri
# and logo_uri are inserted in portal pages, unescaped before LLNG 2.24
# (LLNG issues #3827 and #3838). A logo is kept if it is a plain http(s) URL.
# @param $client_metadata hashref Client registration metadata
# @return 1 if acceptable, 0 otherwise
sub _checkNativeMetadata {
    my ( $self, $client_metadata ) = @_;

    foreach my $field (
        qw(request_uris jwks_uri backchannel_logout_uri frontchannel_logout_uri)
      )
    {
        my $value = $client_metadata->{$field};
        next unless defined $value;
        next if ref($value) eq 'ARRAY' and !@$value;
        $self->logger->error(
                "PACC: Rejecting native client registration with $field "
              . '(strict mode enabled)' );
        return 0;
    }

    my $logo = $client_metadata->{logo_uri};
    if ( defined $logo
        and ( ref $logo or $logo !~ m{\Ahttps?://[^\s"'<>\\`]+\z}i ) )
    {
        $self->logger->error( 'PACC: Rejecting native client registration '
              . 'with a malformed logo_uri (strict mode enabled)' );
        return 0;
    }
    return 1;
}

## @method int allowAnyLoopbackPort($req, $rp, $uri, $endpoint, $state)
# Hook accepting a loopback redirect URI on any port (RFC 8252 section 7.3):
# a native app listens on a port chosen by the system at each login, so the
# port of a declared loopback redirect URI is ignored. Scheme, host, path
# and query must still match exactly. Never refuses: when the URI does not
# qualify, the core performs its usual exact comparison.
# @param $rp configuration key of the RP
# @param $uri redirect URI to validate
# @param $endpoint endpoint that received the URI
# @param $state hashref receiving the validation result
# @return PE_DONE (accepted) or PE_OK (let the core decide)
sub allowAnyLoopbackPort {
    my ( $self, $req, $rp, $uri, $endpoint, $state ) = @_;

    # Enabled by default, also when DefaultValues was not rebuilt
    return PE_OK
      unless ( $self->conf->{paccLoopbackAnyPort} // 1 )
      and $endpoint
      and $endpoint eq 'authorization'
      and defined $uri
      and !ref $uri;

    my $requested = _parseLoopbackUri($uri) or return PE_OK;
    my $allowed =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsRedirectUris} // '';

    foreach my $declared ( split /\s+/, $allowed ) {
        my $candidate = _parseLoopbackUri($declared) or next;
        next
          unless $candidate->{scheme} eq $requested->{scheme}
          and $candidate->{host} eq $requested->{host}
          and $candidate->{path} eq $requested->{path};
        $self->logger->debug(
            "PACC: loopback redirect URI $uri accepted for $rp (any port)");
        $state->{result} = 1;
        return PE_DONE;
    }
    return PE_OK;
}

## @function hashref _parseLoopbackUri($uri)
# Split a loopback URI; scheme and host are lowercased, an empty path is
# read as "/" (RFC 3986 section 6.2.3)
# @return hashref (scheme, host, port, path) or undef if not a loopback URI
sub _parseLoopbackUri {
    my ($uri) = @_;
    my ( $scheme, $host, $port, $path ) = $uri =~ $LOOPBACK_URI or return;
    return if defined $port and ( $port < 1 or $port > 65535 );
    return {
        scheme => lc $scheme,
        host   => lc $host,
        port   => $port,
        path   => ( defined $path and length $path ) ? $path : '/',
    };
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
