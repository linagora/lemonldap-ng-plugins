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
use Encode qw(decode);
use Digest::SHA qw(sha256_hex);
use HTML::Entities qw(encode_entities);
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
);

our $VERSION = '2.23.0';

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

# Set of RPs whose AuthorizationDetailsRules JSON failed to decode.
# Populated as a side effect of _buildRpRarRule. Enforcement treats any
# RAR request for such an RP as denied.
has rpRarBroken => (
    is      => 'rw',
    default => sub { {} },
);

sub init {
    my ($self) = @_;
    return unless $self->SUPER::init;

    # LLNG <= 2.23.2 encodes JSON responses with a non-UTF-8 encoder and
    # then calls utf8::downgrade(), which warns on wide characters. Master
    # enables utf8 on the shared encoder instead. Align older cores so a
    # token response carrying non-ASCII authorization_details is sent as
    # UTF-8 bytes and does not emit "Wide character in subroutine entry".
    $Lemonldap::NG::Common::PSGI::_json->utf8(1)
      if $Lemonldap::NG::Common::PSGI::_json->can('utf8');

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
        my $raw = $opts->{$rp}->{oidcRPMetaDataOptionsAuthorizationDetailsRules};
        next unless defined $raw and length $raw;

        my $perType = eval { decode_json($raw) };
        if ( $@ or ref($perType) ne 'HASH' ) {
            my $why = $@ || 'not a JSON object';
            $self->userLogger->error(
                "RAR: invalid JSON in "
              . "oidcRPMetaDataOptionsAuthorizationDetailsRules for RP $rp: $why"
              . " — denying all authorization_details for this RP" );
            $self->rpRarBroken->{$rp} = 1;
            next;
        }
        next unless %$perType;

        for my $type ( keys %$perType ) {
            my $rule = $perType->{$type};
            next unless defined $rule and length $rule;

            my $expr = $self->p->HANDLER->substitute($rule);
            my $sub  = $self->p->HANDLER->buildSub($expr);
            unless ($sub) {
                my $err = $self->p->HANDLER->tsv->{jail}->error || '???';
                $self->userLogger->error( "RAR: cannot compile rule for RP "
                      . "$rp / type $type: $err — falling back to deny-all "
                      . "to fail closed" );
                $compiled{$rp}{$type} = sub { 0 };
                next;
            }
            $compiled{$rp}{$type} = $sub;
        }
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

# Digest binding a consent token to a relying party and its details.
sub _detailsHash {
    my ( $rp, $raw ) = @_;
    my $bytes = $raw // '';
    utf8::encode($bytes) if utf8::is_utf8($bytes);
    return sha256_hex( $rp . "\0" . $bytes );
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
    # direct authorize calls go through $req->param. Once a pushed request is
    # resolved, only its authorization_details are valid: never fall back to
    # a value added to the front-channel URL.
    my $raw = $oidc_request->{authorization_details};
    unless ( $oidc_request->{_parResolved} ) {
        $raw //= $req->param('authorization_details');

        # The consent form carries the details as a base64 hidden field, so
        # that the JSON quotes do not break the HTML attribute. It is
        # user-controlled: it is re-validated like the parameter above.
        $raw //= $self->p->getHiddenFormValue( $req, 'authorization_details' );
    }

    unless ( defined $raw and length $raw ) {
        delete $req->data->{ &SESSION_KEY };
        delete $req->data->{_rar_unchecked};
        return PE_OK;
    }
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

    # The same value can arrive as raw UTF-8 bytes, as a byte string flagged
    # as characters after a PAR session round-trip, or as genuine wide
    # characters. Downgrade first: when it works, UTF-8-decode the bytes;
    # when it fails, or the UTF-8 decode fails, parse the original as
    # characters.
    my $json;
    my $bytes = $raw;
    if ( utf8::downgrade( $bytes, 1 ) ) {
        my $decoded = $bytes;
        if ( utf8::decode($decoded) ) {
            $json = $decoded;
        }
        elsif ( utf8::is_utf8($raw) ) {
            $json = $raw;
        }
        else {
            $self->logger->error(
                'RAR: authorization_details is not valid UTF-8');
            return PE_ERROR;
        }
    }
    else {
        $json = $raw;
    }

    my $details = eval { JSON->new->decode($json) };
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

    # The consent form is built from the core's parameter list, which does
    # not include authorization_details: carry it through explicitly. The
    # default base64 encoding keeps the JSON quotes out of the HTML attribute,
    # and encoding the characters first keeps encode_base64() from dying on a
    # non-ASCII detail.
    my $hidden = $raw;
    utf8::encode($hidden) if utf8::is_utf8($hidden);
    $self->p->setHiddenFormValue( $req, 'authorization_details', $hidden );

    # Consent is decided from the scopes alone, and the stored consent does
    # not record authorization_details: without this, new details would be
    # granted silently once the scopes were accepted. Force the consent screen
    # and require a token bound to these details, issued by the page below.
    # This does not depend on the core's confirm handling.
    unless ( $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsBypassConsent} )
    {
        my $prompt = $oidc_request->{prompt} // '';
        $oidc_request->{prompt} = join ' ', grep { length } $prompt, 'consent'
          unless $prompt =~ /\bconsent\b/;

        my $cipher = $self->conf->{cipher};
        unless ($cipher) {
            $self->logger->error(
                'RAR: no cipher configured, cannot bind consent to details');
            return PE_ERROR;
        }

        my $hash = _detailsHash( $rp, $raw );
        if ( my $token = $self->p->getHiddenFormValue( $req, 'rar_consent' ) ) {
            my $decoded = eval { $cipher->decrypt($token) };
            my ( $time, $got ) =
              split /:/, ( defined $decoded ? $decoded : '' ), 2;
            if (   $time
                and $got
                and $time > time - 600
                and $got eq $hash )
            {
                $req->data->{_rar_consented} = 1;
            }
            else {
                $self->logger->error('RAR: invalid or stale consent token');
                return PE_ERROR;
            }
        }
        $self->p->setHiddenFormValue( $req, 'rar_consent',
            $cipher->encrypt( time() . ':' . $hash ) );
    }

    $req->data->{ &SESSION_KEY }  = $details;
    $req->data->{_rar_unchecked}  = 1;
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
    return PE_ERROR unless $self->enforceRules( $req, $rp, $details );
    delete $req->data->{_rar_unchecked};

    $code_payload->{ &SESSION_KEY } = $details;
    return PE_OK;
}

# Evaluate the per-RP Perl rules against the current user. Used by the code
# flow (enforceRulesAndStoreOnCode) and by implicit/hybrid flows, where the
# core never fires oidcGenerateCode and addToAccessToken must enforce them.
sub enforceRules {
    my ( $self, $req, $rp, $details ) = @_;

    # bindConsentToDetails() issues a token when the page is built; only a
    # form that posts it back can grant the details. This does not depend on
    # the core accepting a bare confirm=1, nor on a request object's prompt.
    if ( !$self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsBypassConsent}
        and !$req->data->{_rar_consented} )
    {
        $self->logger->error(
            'RAR: authorization_details granted without consent');
        return 0;
    }

    if ( $self->rpRarBroken->{$rp} ) {
        $self->logger->error( "RAR: denying authorization_details for RP $rp "
              . "(rules JSON failed to decode at init)" );
        return 0;
    }

    my $rpRules = $self->rpRarRule->{$rp};
    if ( $rpRules and %$rpRules ) {
        my $user = $req->userData || $req->sessionInfo || {};
        for my $detail (@$details) {
            my $type = $detail->{type};
            my $rule = $rpRules->{$type} or next;
            my $attrs = {
                %$user,
                detail => $detail,
            };
            unless ( $rule->( $req, $attrs ) ) {
                $self->logger->error( "RAR: Perl rule rejected detail of "
                      . "type `$type` for RP $rp" );
                return 0;
            }
        }
    }
    return 1;
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

# Recursively turn decoded characters into UTF-8 bytes (keys included).
# Used only for the JWT payload: the core's _createJWT() uses a non-UTF-8
# to_json(), while sendJSONresponse() and the session backends expect
# characters.
sub _utf8Bytes {
    my ( $self, $value ) = @_;
    if ( ref $value eq 'HASH' ) {
        return {
            map { $self->_utf8Bytes($_) => $self->_utf8Bytes( $value->{$_} ) }
              keys %$value
        };
    }
    if ( ref $value eq 'ARRAY' ) {
        return [ map { $self->_utf8Bytes($_) } @$value ];
    }
    if ( defined $value && !ref $value && utf8::is_utf8($value) ) {
        utf8::encode($value);
    }
    return $value;
}

# Hook: oidcGenerateAccessToken
# Add authorization_details claim to JWT-formatted access tokens (RFC 9396 §7).
# Also persists the details onto the access token session so introspection
# (oidcGenerateIntrospectionResponse) can surface them.
sub addToAccessToken {
    my ( $self, $req, $payload, $rp, $extra_headers ) = @_;
    my $d = $req->data->{ &SESSION_KEY } or return PE_OK;

    # Details parsed from the authorize request are not checked yet. The
    # code flow clears this flag in enforceRulesAndStoreOnCode(); implicit
    # and hybrid flows reach this hook with it set. Never use a request
    # parameter to decide: grant_type can be injected in the authorize URL.
    if ( $req->data->{_rar_unchecked} ) {
        return PE_ERROR unless $self->enforceRules( $req, $rp, $d );
        delete $req->data->{_rar_unchecked};
    }

    $payload->{authorization_details} = $self->_utf8Bytes($d);
    if ( my $jti = $payload->{jti} ) {
        my $update =
          $self->oidc->can('updateState') || $self->oidc->can('updateToken');
        $self->oidc->$update( $jti, { &SESSION_KEY => $d } );
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
#
# The content of `authorization_details` is RP-controlled and lands in HTML,
# so we HTML-escape on the way out: HTML::Template does not auto-escape, and
# operators may forget to add `ESCAPE=HTML` on `<TMPL_VAR NAME="RAR_DETAILS">`.
# Pre-escaping makes the variable safe to render verbatim inside <pre>/<code>.
sub injectConsentDetails {
    my ( $self, $req, $tpl, $args ) = @_;

    return PE_OK unless $$tpl and $$tpl =~ /^oidc.*Consent/;

    my $d = $req->data->{ &SESSION_KEY };
    return PE_OK unless $d;

    my $json = JSON->new->utf8->canonical->pretty->encode($d);
    $json = decode( 'UTF-8', $json );
    $args->{params}->{ &CONSENT_TPL_VAR } = encode_entities($json);
    return PE_OK;
}

1;
