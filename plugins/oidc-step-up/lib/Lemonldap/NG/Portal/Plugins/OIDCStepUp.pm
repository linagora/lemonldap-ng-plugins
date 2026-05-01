package Lemonldap::NG::Portal::Plugins::OIDCStepUp;

# RFC 9470: OAuth 2.0 Step-Up Authentication Challenge — AS side
#
# Adds `acr` and `auth_time` claims to JWT access tokens so a Resource
# Server can decide whether the user's authentication is strong/fresh
# enough for the requested operation, and otherwise emit
# `WWW-Authenticate: Bearer error="insufficient_user_authentication"`
# (the RS-side response is out of this plugin's scope).
#
# The `authenticationLevel → acr` mapping mirrors what core does for ID
# tokens (Lemonldap::NG::Portal::Issuer::OpenIDConnect::_generateIDToken).
#
# Refresh token grants need the original auth_time / authenticationLevel,
# but the LLNG refresh session does not always carry them. We capture
# them on the refresh session at issuance via `oidcGenerateRefreshToken`,
# and restore them on /oauth2/token via `oidcGotTokenRequest`. Auth-code
# grants pick the values from the live user session info directly.

use strict;
use Mouse;
use Lemonldap::NG::Portal::Main::Constants qw(PE_OK);

our $VERSION = '2.23.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

use constant DATA_KEY => '_step_up_claims';

use constant hook => {
    oidcGenerateRefreshToken => 'storeOnRefreshToken',
    oidcGotTokenRequest      => 'restoreOnTokenEndpoint',
    oidcGenerateAccessToken  => 'addClaimsToAccessToken',
};

# Hook: oidcGenerateRefreshToken
# Persist the values needed to recompute acr/auth_time later, on the
# refresh session itself. Only does work when the RP opts in via
# oidcRPMetaDataOptionsStepUpClaims, so unrelated RPs are left alone.
#
# Three sources are tried in order:
#   1. $req->data->{DATA_KEY} — populated by restoreOnTokenEndpoint when
#      a refresh-token rotation happens (back-channel: live sessionInfo
#      is empty here, but the per-request stash carries the original
#      auth context).
#   2. $req->sessionInfo / $req->userData — the live user session, set
#      during the auth_code flow at /authorize.
#   3. $refresh_info itself — core may have already populated `auth_time`
#      and similar fields; pick them up if so.
sub storeOnRefreshToken {
    my ( $self, $req, $refresh_info, $rp, $offline ) = @_;
    return PE_OK unless $self->_enabled($rp);

    my $stash   = $req->data->{ &DATA_KEY }                  || {};
    my $session = $req->sessionInfo || $req->userData         || {};

    my $level =
         $stash->{authenticationLevel}
      // $session->{authenticationLevel}
      // $refresh_info->{authenticationLevel};
    my $atime =
         $stash->{_lastAuthnUTime}
      // $session->{_lastAuthnUTime}
      // $refresh_info->{auth_time};

    $refresh_info->{ &DATA_KEY } = {
        ( defined $level ? ( authenticationLevel => $level + 0 ) : () ),
        ( defined $atime ? ( _lastAuthnUTime     => $atime + 0 ) : () ),
    };
    return PE_OK;
}

# Hook: oidcGotTokenRequest
# At /oauth2/token (back-channel: $req->sessionInfo is empty), pre-load
# the original auth context from the refresh or code session into
# $req->data so addClaimsToAccessToken can pick it up uniformly.
sub restoreOnTokenEndpoint {
    my ( $self, $req, $rp, $grant_type ) = @_;
    return PE_OK unless $self->_enabled($rp);

    if ( $grant_type eq 'refresh_token' ) {
        my $rt = $req->param('refresh_token') or return PE_OK;
        my $rs = $self->oidc->getRefreshToken($rt) or return PE_OK;
        if ( my $stash = $rs->data->{ &DATA_KEY } ) {
            $req->data->{ &DATA_KEY } = $stash;
        }
        elsif ( defined $rs->data->{auth_time}
            or defined $rs->data->{authenticationLevel} )
        {
            # Best-effort fallback for refresh sessions emitted before this
            # plugin was active: read whatever core stored.
            $req->data->{ &DATA_KEY } = {
                (
                    defined $rs->data->{authenticationLevel}
                    ? ( authenticationLevel =>
                          $rs->data->{authenticationLevel} + 0 )
                    : ()
                ),
                (
                    defined $rs->data->{auth_time}
                    ? ( _lastAuthnUTime => $rs->data->{auth_time} + 0 )
                    : ()
                ),
            };
        }
    }
    elsif ( $grant_type eq 'authorization_code' ) {
        my $code = $req->param('code') or return PE_OK;
        my $cs = $self->oidc->getAuthorizationCode($code) or return PE_OK;

        # Code session does not carry _lastAuthnUTime by default. Resolve
        # via user_session_id if present so auth-code grants get a real
        # `auth_time` rather than `iat`.
        my $usid = $cs->data->{user_session_id};
        if ($usid) {
            my $us = $self->p->getApacheSession($usid);
            if ($us) {
                $req->data->{ &DATA_KEY } = {
                    (
                        defined $us->data->{authenticationLevel}
                        ? ( authenticationLevel =>
                              $us->data->{authenticationLevel} + 0 )
                        : ()
                    ),
                    (
                        defined $us->data->{_lastAuthnUTime}
                        ? ( _lastAuthnUTime =>
                              $us->data->{_lastAuthnUTime} + 0 )
                        : ()
                    ),
                };
            }
        }
    }
    return PE_OK;
}

# Hook: oidcGenerateAccessToken
# Inject acr + auth_time into the JWT payload. Reads from the per-request
# stash populated either by restoreOnTokenEndpoint (back-channel) or from
# the live session (other paths).
sub addClaimsToAccessToken {
    my ( $self, $req, $payload, $rp, $extra_headers ) = @_;
    return PE_OK unless $self->_enabled($rp);

    my $stash    = $req->data->{ &DATA_KEY } || {};
    my $session  = $req->sessionInfo || $req->userData || {};
    my $level    =
      defined $stash->{authenticationLevel}
      ? $stash->{authenticationLevel}
      : $session->{authenticationLevel};
    my $atime    =
      defined $stash->{_lastAuthnUTime}
      ? $stash->{_lastAuthnUTime}
      : $session->{_lastAuthnUTime};

    $payload->{auth_time} = $atime + 0 if defined $atime;

    if ( defined $level ) {
        my $acr = "loa-$level";
        my $ctx = $self->conf->{oidcServiceMetaDataAuthnContext} || {};

        # Sort keys for determinism: if two ACR names map to the same
        # authenticationLevel (legitimate but ambiguous config), the chosen
        # name must not depend on Perl's hash randomization across runs.
        for my $name ( sort keys %$ctx ) {
            if ( $ctx->{$name} eq $level ) {
                $acr = $name;
                last;
            }
        }
        $payload->{acr} = $acr;
    }
    return PE_OK;
}

sub _enabled {
    my ( $self, $rp ) = @_;
    return $self->oidc->rpOptions->{$rp}
      ->{oidcRPMetaDataOptionsStepUpClaims} ? 1 : 0;
}

1;
