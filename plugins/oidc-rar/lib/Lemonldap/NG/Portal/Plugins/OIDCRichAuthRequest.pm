# RFC 9396 - OAuth 2.0 Rich Authorization Requests (RAR)
#
# This plugin adds support for the `authorization_details` parameter on the
# OIDC Provider side. It validates and persists the parameter through the
# authorization_code and refresh_token flows, echoes it in token responses,
# exposes it as a JWT access token claim and via introspection, and
# advertises supported types in the discovery document.
package Lemonldap::NG::Portal::Plugins::OIDCRichAuthRequest;

use strict;
use Mouse;
use JSON qw(decode_json);
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
);

our $VERSION = '0.1.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

use constant SESSION_KEY      => '_rar_details';
use constant CONSENT_TPL_VAR  => 'RAR_DETAILS';

use constant hook => {
    oidcGotRequest                    => 'parseAuthorizationDetails',
    oidcGenerateCode                  => 'enforceRulesAndStoreOnCode',
    oidcGotTokenRequest               => 'loadDetailsAtTokenEndpoint',
    oidcGenerateRefreshToken          => 'storeOnRefresh',
    oidcGotOnlineRefresh              => 'restoreFromRefresh',
    oidcGotOfflineRefresh             => 'restoreFromRefresh',
    oidcGenerateAccessToken           => 'addToAccessToken',
    oidcGenerateTokenResponse         => 'addToTokenResponse',
    oidcGenerateIntrospectionResponse => 'addToIntrospection',
    oidcGenerateMetadata              => 'advertiseTypes',
    sendHtml                          => 'injectConsentDetails',
};

has globalAllowedTypes => (
    is      => 'ro',
    lazy    => 1,
    builder => '_buildGlobalAllowedTypes',
);

has rpAllowedTypes => (
    is      => 'ro',
    lazy    => 1,
    builder => '_buildRpAllowedTypes',
);

has rpRarRule => (
    is      => 'ro',
    lazy    => 1,
    builder => '_buildRpRarRule',
);

sub init {
    my ($self) = @_;
    return unless $self->SUPER::init;

    # Force lazy builders so configuration errors surface at init time
    $self->globalAllowedTypes;
    $self->rpAllowedTypes;
    $self->rpRarRule;

    return 1;
}

sub _buildGlobalAllowedTypes {
    my ($self) = @_;
    return _parseTypeList( $self->conf->{oidcServiceAuthorizationDetailsTypes} );
}

sub _buildRpAllowedTypes {
    my ($self) = @_;
    my %map;
    my $opts = $self->conf->{oidcRPMetaDataOptions} || {};
    for my $rp ( keys %$opts ) {
        next
          unless $opts->{$rp}->{oidcRPMetaDataOptionsAuthorizationDetailsEnabled};
        $map{$rp} = _parseTypeList(
            $opts->{$rp}->{oidcRPMetaDataOptionsAuthorizationDetailsTypes} );
    }
    return \%map;
}

sub _buildRpRarRule {
    my ($self) = @_;
    my %compiled;
    my $opts = $self->conf->{oidcRPMetaDataOptions} || {};
    for my $rp ( keys %$opts ) {
        next
          unless $opts->{$rp}->{oidcRPMetaDataOptionsAuthorizationDetailsEnabled};
        my $rule = $opts->{$rp}->{oidcRPMetaDataOptionsAuthorizationDetailsRule};
        next unless defined $rule and length $rule;

        my $expr = $self->p->HANDLER->substitute($rule);
        my $sub  = $self->p->HANDLER->buildSub($expr);
        unless ($sub) {
            $self->logger->error( "RAR: cannot compile rule for RP $rp: "
                  . $self->p->HANDLER->tsv->{jail}->error );
            next;
        }
        $compiled{$rp} = $sub;
    }
    return \%compiled;
}

sub _parseTypeList {
    my ($list) = @_;
    return {} unless defined $list and length $list;
    my %set;
    for my $t ( split /\s*,\s*/, $list ) {
        $set{$t} = 1 if length $t;
    }
    return \%set;
}

# Hook: oidcGotRequest
# Layer 1 only (type allowlist). The Perl rule is enforced later, once user
# attributes are known, in oidcGenerateCode.
#
# `authorization_details` is not in the core's hardcoded parameter list
# (Issuer/OpenIDConnect.pm), so it is absent from $oidc_request — read it
# directly from $req. Echo it back into $oidc_request for downstream hooks.
sub parseAuthorizationDetails {
    my ( $self, $req, $oidc_request ) = @_;

    # PAR (oidc-par plugin) populates $oidc_request from a stored PAR session;
    # direct authorize calls go through $req->param. Try both.
    my $raw = $oidc_request->{authorization_details}
      // $req->param('authorization_details');
    return PE_OK unless defined $raw and length $raw;
    $oidc_request->{authorization_details} = $raw;

    my $client_id = $oidc_request->{client_id};
    my $rp        = $client_id ? $self->oidc->getRP($client_id) : undef;
    unless ($rp) {
        $self->logger->error(
            "RAR: client_id $client_id has no matching RP, ignoring "
              . "authorization_details" );
        return PE_OK;
    }

    unless ( $self->oidc->rpOptions->{$rp}
        ->{oidcRPMetaDataOptionsAuthorizationDetailsEnabled} )
    {
        $self->logger->error("RAR: not enabled for RP $rp");
        return PE_ERROR;
    }

    my $details = eval { decode_json($raw) };
    if ($@) {
        $self->logger->error("RAR: malformed authorization_details JSON: $@");
        return PE_ERROR;
    }

    unless ( ref($details) eq 'ARRAY' and @$details ) {
        $self->logger->error(
            "RAR: authorization_details must be a non-empty JSON array");
        return PE_ERROR;
    }

    my $globalSet = $self->globalAllowedTypes;
    my $rpSet     = $self->rpAllowedTypes->{$rp} || {};

    for my $detail (@$details) {
        unless ( ref($detail) eq 'HASH' ) {
            $self->logger->error("RAR: each detail must be a JSON object");
            return PE_ERROR;
        }
        my $type = $detail->{type};
        unless ( defined $type and !ref($type) and length $type ) {
            $self->logger->error(
                "RAR: each detail must have a non-empty `type` string");
            return PE_ERROR;
        }
        if ( %$globalSet and !$globalSet->{$type} ) {
            $self->logger->error(
                "RAR: type `$type` not in service-level allowlist");
            return PE_ERROR;
        }
        if ( %$rpSet and !$rpSet->{$type} ) {
            $self->logger->error(
                "RAR: type `$type` not in RP `$rp` allowlist");
            return PE_ERROR;
        }
    }

    $req->data->{ &SESSION_KEY } = $details;
    $self->logger->debug(
        "RAR: validated " . scalar(@$details) . " authorization_details" );

    return PE_OK;
}

# Hook: oidcGenerateCode
# Runs after authentication and consent. Enforces the per-RP Perl rule against
# the now-known user attributes, then persists granted details on the code
# session so subsequent token/refresh calls can echo them.
sub enforceRulesAndStoreOnCode {
    my ( $self, $req, $oidc_request, $rp, $code_payload ) = @_;

    my $details = $req->data->{ &SESSION_KEY } or return PE_OK;

    my $rule = $self->rpRarRule->{$rp};
    if ($rule) {
        for my $detail (@$details) {
            my $attrs = {
                %{ $req->userData || {} },
                type   => $detail->{type},
                detail => $detail,
            };
            unless ( $rule->( $req, $attrs ) ) {
                $self->logger->error( "RAR: Perl rule rejected detail of "
                      . "type `$detail->{type}` for RP $rp" );
                return PE_ERROR;
            }
        }
    }

    $code_payload->{ &SESSION_KEY } = $details;
    return PE_OK;
}

# Hook: oidcGotTokenRequest
# At /oauth2/token entry, $req->data is empty (back-channel call). Load
# _rar_details from the code session (authorization_code grant) or the refresh
# session (refresh_token grant) so the rest of the token-endpoint hook chain
# can find them on $req->data.
sub loadDetailsAtTokenEndpoint {
    my ( $self, $req, $rp, $grant_type ) = @_;

    if ( $grant_type eq 'authorization_code' ) {
        my $code = $req->param('code') or return PE_OK;
        my $codeSession = $self->oidc->getAuthorizationCode($code) or return PE_OK;
        if ( my $d = $codeSession->data->{ &SESSION_KEY } ) {
            $req->data->{ &SESSION_KEY } = $d;
        }
    }
    elsif ( $grant_type eq 'refresh_token' ) {
        my $rt = $req->param('refresh_token') or return PE_OK;
        my $refreshSession = $self->oidc->getRefreshToken($rt) or return PE_OK;
        if ( my $d = $refreshSession->data->{ &SESSION_KEY } ) {
            $req->data->{ &SESSION_KEY } = $d;
        }
    }
    return PE_OK;
}

# Hook: oidcGenerateRefreshToken
# Persist details on the refresh session so refresh_token grants can echo them.
sub storeOnRefresh {
    my ( $self, $req, $refresh_info, $rp, $offline ) = @_;

    my $details = $req->data->{ &SESSION_KEY };
    $refresh_info->{ &SESSION_KEY } = $details if $details;
    return PE_OK;
}

# Hooks: oidcGotOnlineRefresh / oidcGotOfflineRefresh
# Restore details from the refresh session into $req->data so the rest of the
# token response pipeline (addToAccessToken, addToTokenResponse) can find them.
sub restoreFromRefresh {
    my ( $self, $req, $rp, $refreshInfo, $sessionInfo ) = @_;

    if ( my $d = $refreshInfo->{ &SESSION_KEY } ) {
        $req->data->{ &SESSION_KEY } = $d;
    }
    return PE_OK;
}

# Hook: oidcGenerateAccessToken
# Add authorization_details claim to JWT-formatted access tokens (RFC 9396 §7).
# Also persists the details onto the access token session so introspection
# (oidcGenerateIntrospectionResponse) can surface them.
sub addToAccessToken {
    my ( $self, $req, $payload, $rp, $extra_headers ) = @_;
    my $d = $req->data->{ &SESSION_KEY } or return PE_OK;

    $payload->{authorization_details} = $d;
    if ( my $jti = $payload->{jti} ) {
        $self->oidc->updateToken( $jti, { &SESSION_KEY => $d } );
    }
    return PE_OK;
}

# Hook: oidcGenerateTokenResponse
# Echo authorization_details in the token endpoint JSON response (RFC 9396 §6).
sub addToTokenResponse {
    my ( $self, $req, $rp, $tokensResponse, $oidcSession, $userSession,
        $grant_type ) = @_;

    my $d = $oidcSession->{ &SESSION_KEY } || $req->data->{ &SESSION_KEY };
    $tokensResponse->{authorization_details} = $d if $d;
    return PE_OK;
}

# Hook: oidcGenerateIntrospectionResponse
# Expose authorization_details on RFC 7662 introspection (RFC 9396 §10).
sub addToIntrospection {
    my ( $self, $req, $response, $rp, $token_data ) = @_;
    if ( my $d = $token_data->{ &SESSION_KEY } ) {
        $response->{authorization_details} = $d;
    }
    return PE_OK;
}

# Hook: oidcGenerateMetadata
# Advertise authorization_details_types_supported in /.well-known/openid-configuration
# (RFC 9396 §11). Computed as the union of every enabled RP's allowed types,
# intersected with the global allowlist when set.
sub advertiseTypes {
    my ( $self, $req, $metadata ) = @_;

    my %union;
    for my $rp ( keys %{ $self->rpAllowedTypes } ) {
        $union{$_} = 1 for keys %{ $self->rpAllowedTypes->{$rp} };
    }
    my $globalSet = $self->globalAllowedTypes;
    if ( %$globalSet ) {
        if ( %union ) {
            %union = map { $_ => 1 } grep { $globalSet->{$_} } keys %union;
        }
        else {
            %union = %$globalSet;
        }
    }

    if ( %union ) {
        $metadata->{authorization_details_types_supported} =
          [ sort keys %union ];
    }
    return PE_OK;
}

# Hook: sendHtml
# Inject a pretty-printed JSON view of pending authorization_details for the
# OIDC consent template, so deployments that render the variable can show it
# to the user.
sub injectConsentDetails {
    my ( $self, $req, $tpl, $args ) = @_;

    return PE_OK unless $$tpl and $$tpl =~ /^oidc.*Consent/;

    my $d = $req->data->{ &SESSION_KEY };
    return PE_OK unless $d;

    $args->{params}->{ &CONSENT_TPL_VAR } =
      JSON->new->canonical->pretty->encode($d);
    return PE_OK;
}

1;
