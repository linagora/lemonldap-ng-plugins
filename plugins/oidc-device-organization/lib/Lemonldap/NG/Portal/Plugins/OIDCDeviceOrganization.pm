package Lemonldap::NG::Portal::Plugins::OIDCDeviceOrganization;

# Organizational Device Authorization - Extension to RFC 8628
#
# When a RP is configured with oidcRPMetaDataOptionsDeviceOwnership='organization',
# the tokens issued via Device Authorization Grant identify the *client application*
# (the enrolled device) rather than the *admin who approved* the enrollment.
#
# This is useful for enrolling servers, kiosks, smart TVs, etc. that belong to
# the organization. The admin approves the enrollment but the resulting token
# survives the admin leaving the organization.
#
# Implementation: hooks into oidcDeviceCodeGrant (provided by OIDCDeviceAuthorization
# plugin) and replaces the user session data with a synthetic session whose identity
# is the client_id.

use strict;
use Mouse;
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
    oidcDeviceCodeGrant  => 'handleOrganizationDevice',
    oidcGenerateMetadata => 'addDeviceAuthMetadata',
};

sub init {
    my ($self) = @_;
    unless ( $self->conf->{issuerDBOpenIDConnectActivation} ) {
        $self->logger->error(
            'OIDC issuer not enabled, OIDCDeviceOrganization disabled');
        return 0;
    }
    1;
}

# Hook: oidcDeviceCodeGrant
# Called by OIDCDeviceAuthorization._generateTokens() after PKCE validation
# and before token creation.
sub handleOrganizationDevice {
    my ( $self, $req, $device_auth, $rp, $session_data ) = @_;

    # Check if this RP uses organizational device ownership
    my $ownership =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsDeviceOwnership}
      // '';
    return PE_OK unless $ownership eq 'organization';

    my $client_id   = $device_auth->{client_id};
    my $approved_by = $device_auth->{user};

    $self->logger->debug(
        "Organization device enrollment: client=$client_id approved_by=$approved_by"
    );

    # Build synthetic session data (same pattern as client_credentials grant)
    my $infos = {
        $self->conf->{whatToTrace} => $client_id,
        _clientId                  => $client_id,
        _clientConfKey             => $rp,
        _scope                     => $device_auth->{scope},
        _user                      => $client_id,
        _approved_by               => $approved_by,
        _approved_at => $device_auth->{approved_at} || time,
        _deviceOrg                 => 1,

        # Set _utime far enough in the future so this session outlives
        # normal SSO sessions. The device will use refresh tokens to
        # get new access tokens, and the refresh points back to this
        # session. In production, oidcRPMetaDataOptionsOfflineSessionExpiration
        # on the RP controls the refresh token lifetime.
        _utime => time + ( $self->conf->{oidcServiceOfflineSessionExpiration}
              || 365 * 86400 ),
    };

    my $session = $self->p->getApacheSession( undef, info => $infos );
    unless ($session) {
        $self->logger->error(
            "Failed to create synthetic session for org device");
        return PE_OK;    # Fall back to normal user-linked behavior
    }

    # Point to the new synthetic session instead of the admin's
    $device_auth->{user_session_id} = $session->id;

    # Remove offline_access from scope to force online refresh token
    # (offline would try to resolve client_id in UserDB and fail)
    $device_auth->{scope} =~ s/\boffline_access\b//g;
    $device_auth->{scope} =~ s/\s+/ /g;
    $device_auth->{scope} =~ s/^\s+|\s+$//g;

    # Replace session_data so tokens carry synthetic attributes
    %$session_data = %{ $session->data };

    $self->userLogger->notice(
"Organization device enrolled: client=$client_id for RP $rp (approved by $approved_by)"
    );

    $self->auditLog(
        $req,
        code        => "ISSUER_OIDC_DEVICE_ORG_ENROLLED",
        rp          => $rp,
        client_id   => $client_id,
        approved_by => $approved_by,
        message     =>
"Organization device $client_id enrolled for RP $rp by $approved_by",
    );

    return PE_OK;
}

# Hook: oidcGenerateMetadata
# Advertise device_authorization_endpoint in discovery if any RP allows it
sub addDeviceAuthMetadata {
    my ( $self, $req, $metadata ) = @_;
    my $issuer = $metadata->{issuer};
    my $path   = $self->oidc->path . '/';
    $path = '/' . $path unless $issuer =~ /\/$/;
    $metadata->{device_authorization_endpoint} =
      $issuer . $path . 'device';
    return PE_OK;
}

1;
