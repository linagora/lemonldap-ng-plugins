package Lemonldap::NG::Portal::Plugins::OIDCGrantManagement;

# FAPI Grant Management for OAuth 2.0
# https://openid.net/specs/fapi-grant-management.html
#
# Adds:
#   * `grant_management_action` parameter on /oauth2/authorize
#     (`create` / `update` / `replace`)
#   * `grant_id` field in token responses
#   * RESTful endpoint at /oauth2/{grant_management_uri}/{grant_id}
#     - GET    => return JSON description of the grant
#     - DELETE => revoke the grant
#   * Discovery fields `grant_management_actions_supported` and
#     `grant_management_endpoint`
#
# Grants are stored as a dedicated session kind. The grant id is the LLNG
# session id, so client-presented grant_ids resolve straight to a session
# lookup with no search-by-attribute.
#
# Token cascade revocation on DELETE is BEST-EFFORT in this v1: only the
# grant session is removed. Already-issued access tokens stay valid until
# their TTL expires. Operators wanting hard revocation can shorten the AT
# TTL or pair the plugin with a custom userinfo/introspection hook that
# re-checks the grant.

use strict;
use Mouse;
use JSON;
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
  PE_SENDRESPONSE
);

our $VERSION = '2.24.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

use constant SESSION_KIND     => 'OIDCGrant';
use constant DATA_KEY         => '_grant_ctx';
use constant SUPPORTED_ACTIONS => [qw(create update replace)];

use constant hook => {
    oidcGotRequest                    => 'parseGrantManagementParam',
    oidcGenerateCode                  => 'materializeGrantAndStoreOnCode',
    oidcGotTokenRequest               => 'restoreOnTokenEndpoint',
    oidcGenerateRefreshToken          => 'storeOnRefresh',
    oidcGenerateTokenResponse         => 'echoGrantId',
    oidcGenerateAccessToken           => 'addGrantIdToAccessToken',
    oidcGenerateIntrospectionResponse => 'addGrantIdToIntrospection',
    oidcGenerateMetadata              => 'advertiseEndpoint',
};

sub init {
    my ($self) = @_;
    return unless $self->SUPER::init;

    my $uri = $self->conf->{oidcServiceMetaDataGrantManagementURI}
      || 'grants';

    # Register the RESTful endpoint at /<oidc-path>/<uri>/<grant_id>.
    # The PSGI router supports `:name` to capture path components into
    # request params (cf. Lemonldap::NG::Common::PSGI::Router doc).
    $self->addUnauthRoute(
        $self->oidc->path => {
            $uri => {
                ':grant_id' => 'handleGrantEndpoint',
            }
        },
        [ 'GET', 'DELETE' ],
    );
    return 1;
}

# ---------------------------------------------------------------------------
# Hooks on /oauth2/authorize

# Hook: oidcGotRequest
# Parse `grant_management_action` and `grant_id` from the request, validate
# against the per-RP mode, and stash on $req->data->{DATA_KEY} so the rest
# of the flow can act on it.
sub parseGrantManagementParam {
    my ( $self, $req, $oidc_request ) = @_;

    my $client_id = $oidc_request->{client_id} or return PE_OK;
    my $rp = $self->oidc->getRP($client_id) or return PE_OK;
    my $mode = $self->oidc->rpOptions->{$rp}
      ->{oidcRPMetaDataOptionsGrantManagement} // '';

    # A PAR request_uri is resolved by oidc-par later in the same hook chain.
    # Until then the request is not known: neither enforce the required mode
    # nor reject a browser-side value. oidc-par calls this hook back once the
    # pushed request is resolved, whatever the plugin order.
    if (   $oidc_request->{request_uri}
        and not $oidc_request->{_parResolved}
        and $self->p->loadedModules->{
            'Lemonldap::NG::Portal::Plugins::OIDCPushedAuthRequest'}
        and $oidc_request->{request_uri} =~
        m{^urn:ietf:params:oauth:request_uri:} )
    {
        return PE_OK;
    }

    # Once a pushed request is resolved, only its values are valid: never
    # fall back to the front-channel parameters (RFC 9126 section 3).
    my $action   = $oidc_request->{grant_management_action};
    my $grant_id = $oidc_request->{grant_id};
    unless ( $oidc_request->{_parResolved} ) {
        $action   //= $req->param('grant_management_action');
        $grant_id //= $req->param('grant_id');
    }

    # Defensive: drop any context an earlier hook may have stored, so a
    # resolved request without an action cannot reuse a browser-side value.
    unless ( defined $action and length $action ) {
        delete $req->data->{ &DATA_KEY };

        # If the RP requires Grant Management, every authorize MUST carry an
        # action. In `allowed` mode the action is strictly opt-in: requests
        # without `grant_management_action` produce no `grant_id`. (The FAPI
        # draft has gone back and forth on whether `create` is the implicit
        # default; this plugin currently treats absence as "no grant", which
        # is also what the test suite asserts.)
        if ( $mode eq 'required' ) {
            $self->logger->error(
                "OIDCGrantManagement: RP `$rp` requires grant_management_action "
                  . "and the request did not provide one" );
            return PE_ERROR;
        }
        return PE_OK;
    }

    return PE_OK unless $mode eq 'allowed' or $mode eq 'required';

    unless ( grep { $_ eq $action } @{ &SUPPORTED_ACTIONS } ) {
        $self->logger->error(
            "OIDCGrantManagement: unsupported grant_management_action "
              . "`$action` (only "
              . join( '/', @{ &SUPPORTED_ACTIONS } )
              . " are supported)" );
        return PE_ERROR;
    }

    # The grant is materialized in materializeGrantAndStoreOnCode, which the
    # core only fires on the authorization code flow. On implicit and hybrid
    # flows the action would be accepted and never applied: refuse it, so the
    # client knows the grant did not change. The materialized flag checked in
    # addGrantIdToAccessToken is a second guard.
    my $response_type = $oidc_request->{response_type};
    if (    defined $response_type
        and length $response_type
        and $response_type ne 'code' )
    {
        $self->logger->error(
            "OIDCGrantManagement: grant_management_action is only supported on "
              . "the authorization code flow (got response_type "
              . "`$response_type` for RP $rp)" );
        return PE_ERROR;
    }

    if ( $action ne 'create' ) {
        unless ($grant_id) {
            $self->logger->error(
                "OIDCGrantManagement: action `$action` requires grant_id" );
            return PE_ERROR;
        }
        my $grant = $self->_loadGrant($grant_id);
        unless ($grant) {
            $self->logger->error(
                "OIDCGrantManagement: grant `$grant_id` not found");
            return PE_ERROR;
        }
        if ( $grant->data->{client_id} ne
            ( $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID}
                || '' ) )
        {
            $self->logger->error(
                "OIDCGrantManagement: grant `$grant_id` belongs to a "
                  . "different client" );
            return PE_ERROR;
        }
    }

    $req->data->{ &DATA_KEY } = {
        action       => $action,
        grant_id     => $grant_id,
        rp           => $rp,
        materialized => 0,
    };
    return PE_OK;
}

# Hook: oidcGenerateCode
# Materialize the grant NOW (during /authorize) so the grant_id is known
# before any access token is built. For action=create or default, mint a
# fresh session whose id IS the grant_id. For update/replace, merge the
# requested scope/details into the existing grant. Persist the resulting
# grant_id on the code session so the back-channel /oauth2/token call can
# read it.
sub materializeGrantAndStoreOnCode {
    my ( $self, $req, $oidc_request, $rp, $code_payload ) = @_;
    my $ctx = $req->data->{ &DATA_KEY } or return PE_OK;

    # The core fires this hook on the authorization code flow only. Keep a
    # guard in case that changes: implicit and hybrid flows must not end up
    # with a grant that the plugin cannot apply.
    my $response_type = $oidc_request->{response_type};
    if (    defined $response_type
        and length $response_type
        and $response_type ne 'code' )
    {
        $self->logger->error(
            "OIDCGrantManagement: cannot materialize a grant outside the "
              . "authorization code flow (response_type `$response_type`)" );
        return PE_ERROR;
    }

    # oidc-rar applies its per-RP rules in its own oidcGenerateCode hook,
    # whose order relative to this one is not guaranteed. Apply them now when
    # they have not run yet: never record authorization_details in the grant
    # that oidc-rar refuses. Its own hook runs the same rules again
    # afterwards, which is harmless.
    if ( my $details = $req->data->{_rar_details} ) {
        my $rar = $self->p->loadedModules
          ->{'Lemonldap::NG::Portal::Plugins::OIDCRichAuthRequest'};
        if ( $rar and $rar->can('enforceRules') ) {
            if ( $req->data->{_rar_unchecked} ) {
                return PE_ERROR
                  unless $rar->enforceRules( $req, $rp, $details );
            }
        }
        else {

            # oidc-rar is older than this plugin: its rules cannot run here
            # and its own hook may run after this one. Fail closed instead of
            # recording details that may be refused afterwards.
            $self->logger->error(
                "OIDCGrantManagement: oidc-rar is too old to enforce the "
                  . "authorization_details rules before storing the grant" );
            return PE_ERROR;
        }
    }

    my $action    = $ctx->{action};
    my $grant_id  = $ctx->{grant_id};
    my $client_id =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};
    my $sub =
         $req->sessionInfo->{ $self->conf->{whatToTrace} }
      || $req->userData->{ $self->conf->{whatToTrace} }
      || '';
    my $scope = $code_payload->{scope} || '';
    my $rar   = $req->data->{_rar_details};   # set by oidc-rar if loaded
    my $ttl = $self->conf->{oidcServiceGrantExpiration} || 7776000;

    if ( $action eq 'create' ) {
        my $session = $self->oidc->getOpenIDConnectSession(
            undef,
            &SESSION_KIND,
            ttl  => $ttl,
            info => {
                rp                    => $rp,
                client_id             => $client_id,
                sub                   => $sub,
                scope                 => $scope,
                authorization_details => $rar,
                created_at            => time,
                last_used_at          => time,
            }
        );
        return PE_OK unless $session;
        $grant_id = $session->id;
    }
    elsif ($grant_id) {
        my $grant = $self->_loadGrant($grant_id) or do {
            $self->logger->error(
                "OIDCGrantManagement: grant `$grant_id` vanished between "
                  . "parse and code generation" );
            return PE_ERROR;
        };

        # Subject check: a client presenting a stolen `grant_id` must NOT
        # be able to update/replace another user's grant. The user is
        # authenticated by the time oidcGenerateCode fires, so we can
        # compare the grant owner against the current session.
        my $grant_sub = $grant->data->{sub} // '';
        if ( length $grant_sub and $grant_sub ne $sub ) {
            $self->logger->error(
                "OIDCGrantManagement: grant `$grant_id` is owned by a "
                  . "different subject (got `$sub`, expected `$grant_sub`)"
            );
            return PE_ERROR;
        }

        my %merged_scope =
          map { $_ => 1 } split /\s+/, $grant->data->{scope} || '';

        # `authorization_details` (RFC 9396, set by oidc-rar when active)
        # follows the same semantics as `scope`:
        #   - update  => union of existing + new entries (deduped by `type`)
        #   - replace => entries from the current request only
        my $existing_rar = $grant->data->{authorization_details};
        my $new_rar;
        if ( $action eq 'update' ) {
            $merged_scope{$_} = 1 for split /\s+/, $scope;
            $new_rar = _mergeRar( $existing_rar, $rar );
        }
        elsif ( $action eq 'replace' ) {
            %merged_scope = map { $_ => 1 } split /\s+/, $scope;
            $new_rar = $rar;
        }

        $grant->update( {
                scope => join( ' ', sort keys %merged_scope ),
                (
                    defined $new_rar
                    ? ( authorization_details => $new_rar )
                    : ()
                ),
                last_used_at => time,
        } );
    }

    $ctx->{grant_id}     = $grant_id;
    $ctx->{materialized} = 1;
    $code_payload->{ &DATA_KEY } = $ctx;
    return PE_OK;
}

# ---------------------------------------------------------------------------
# Hooks on /oauth2/token

# Hook: oidcGotTokenRequest
# Restore grant context from code or refresh session into $req->data so the
# response-building hooks below can act on it.
sub restoreOnTokenEndpoint {
    my ( $self, $req, $rp, $grant_type ) = @_;

    if ( $grant_type eq 'authorization_code' ) {
        my $code = $req->param('code') or return PE_OK;
        my $cs = $self->oidc->getAuthorizationCode($code) or return PE_OK;
        if ( my $ctx = $cs->data->{ &DATA_KEY } ) {

            # Anything stored on a code session was materialized by
            # materializeGrantAndStoreOnCode. The flag is absent from grants
            # created before it existed: set it so their grant_id keeps
            # flowing after an upgrade.
            $ctx->{materialized} = 1;
            $req->data->{ &DATA_KEY } = $ctx;
        }
    }
    elsif ( $grant_type eq 'refresh_token' ) {
        my $rt = $req->param('refresh_token') or return PE_OK;
        my $rs = $self->oidc->getRefreshToken($rt) or return PE_OK;
        if ( my $ctx = $rs->data->{ &DATA_KEY } ) {
            $ctx->{materialized} = 1;
            $req->data->{ &DATA_KEY } = $ctx;
        }
    }
    return PE_OK;
}

# Hook: oidcGenerateRefreshToken
# Carry the grant context onto refresh sessions so it survives rotation.
sub storeOnRefresh {
    my ( $self, $req, $refresh_info, $rp, $offline ) = @_;
    my $ctx = $req->data->{ &DATA_KEY } or return PE_OK;
    $refresh_info->{ &DATA_KEY } = $ctx;
    return PE_OK;
}

# Hook: oidcGenerateTokenResponse
# The grant has already been materialized at /authorize time
# (materializeGrantAndStoreOnCode). All this hook does is echo grant_id
# back to the client in the JSON token response.
sub echoGrantId {
    my ( $self, $req, $rp, $tokensResponse, $oidcSession, $userSession,
        $grant_type )
      = @_;
    my $ctx = $req->data->{ &DATA_KEY } || $oidcSession->{ &DATA_KEY }
      or return PE_OK;
    my $grant_id = $ctx->{grant_id} or return PE_OK;
    $tokensResponse->{grant_id} = $grant_id;
    return PE_OK;
}

# Hook: oidcGenerateAccessToken
# Add the `grant_id` claim to the JWT access token. Also patches the AT
# session post-creation (via updateToken) so introspection can surface it.
sub addGrantIdToAccessToken {
    my ( $self, $req, $payload, $rp, $extra_headers ) = @_;
    my $ctx = $req->data->{ &DATA_KEY } or return PE_OK;
    my $grant_id = $ctx->{grant_id} or return PE_OK;

    # Fail closed: only a grant materialized for this authorization, or
    # restored from a code or refresh session, may be attached to a token.
    # On implicit and hybrid flows the action is not processed, and a
    # grant_id taken from the request may belong to another user, so drop
    # the claim. Returning PE_ERROR would not be enough: the implicit branch
    # of the core still issues the ID token when the access token fails.
    unless ( $ctx->{materialized} ) {
        $self->logger->error(
            "OIDCGrantManagement: not adding grant `$grant_id` to the access "
              . "token: the grant was not materialized for this request" );
        return PE_OK;
    }

    $payload->{grant_id} = $grant_id;
    if ( my $jti = $payload->{jti} ) {
        my $update =
          $self->oidc->can('updateState') || $self->oidc->can('updateToken');
        $self->oidc->$update( $jti, { grant_id => $grant_id } );
    }
    return PE_OK;
}

# Hook: oidcGenerateIntrospectionResponse
sub addGrantIdToIntrospection {
    my ( $self, $req, $response, $rp, $token_data ) = @_;
    if ( my $grant_id = $token_data->{grant_id} ) {
        $response->{grant_id} = $grant_id;
    }
    return PE_OK;
}

# Hook: oidcGenerateMetadata
# Advertise grant_management_endpoint and grant_management_actions_supported
# in /.well-known/openid-configuration.
sub advertiseEndpoint {
    my ( $self, $req, $metadata ) = @_;
    my $issuer = $metadata->{issuer};
    my $uri    = $self->conf->{oidcServiceMetaDataGrantManagementURI}
      || 'grants';
    my $sep = $issuer =~ m{/$} ? '' : '/';
    $metadata->{grant_management_endpoint} =
      $issuer . $sep . $self->oidc->path . '/' . $uri;
    $metadata->{grant_management_actions_supported} =
      [ @{ &SUPPORTED_ACTIONS } ];
    return PE_OK;
}

# ---------------------------------------------------------------------------
# RESTful endpoint /oauth2/grants/{grant_id}

sub handleGrantEndpoint {
    my ( $self, $req ) = @_;

    my $grant_id = $req->param('grant_id')
      or return $self->_jsonError( $req, 400, 'invalid_request',
        'grant_id is required' );

    my ( $rp, $auth_method ) =
      $self->oidc->checkEndPointAuthenticationCredentials($req);
    return $self->oidc->invalidClientResponse($req) unless $rp;

    # The grant endpoint serves only a caller that proved it is the client.
    # A bare client_id (`none`) proves nothing: the token endpoint accepts it
    # because PKCE protects the code there, which is not the case here.
    if ( !$auth_method or $auth_method eq 'none' ) {
        $self->logger->error(
            "OIDCGrantManagement: grant endpoint called without client "
              . "authentication" );
        return $self->oidc->invalidClientResponse($req);
    }

    # A public client certificate is not checked by the core: tls_client_auth
    # is only validated in its confidential branch. A registered client
    # secret and the JWS methods are accepted, as the core verifies them for
    # a public client too.
    if (    $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsPublic}
        and $auth_method eq 'tls_client_auth' )
    {
        $self->logger->error(
            "OIDCGrantManagement: public client `$rp` cannot authenticate "
              . "with a client certificate on the grant endpoint" );
        return $self->oidc->invalidClientResponse($req);
    }

    my $client_id =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};

    my $grant = $self->_loadGrant($grant_id);
    return $self->_jsonError( $req, 404, 'invalid_grant',
        'No such grant_id' )
      unless $grant;

    if ( ( $grant->data->{client_id} || '' ) ne $client_id ) {
        $self->logger->error( "OIDCGrantManagement: client `$client_id` "
              . "tried to access grant `$grant_id` owned by "
              . ( $grant->data->{client_id} // '<undef>' ) );
        return $self->_jsonError( $req, 403, 'invalid_grant',
            'Grant does not belong to this client' );
    }

    my $method = uc( $req->env->{REQUEST_METHOD} || 'GET' );
    if ( $method eq 'GET' ) {
        return $self->_grantGet( $req, $grant );
    }
    elsif ( $method eq 'DELETE' ) {
        return $self->_grantDelete( $req, $grant, $rp );
    }
    return $self->_jsonError( $req, 405, 'invalid_request',
        "Method $method not allowed" );
}

sub _grantGet {
    my ( $self, $req, $grant ) = @_;
    my $body = {
        scopes => [
            map { { scope => $_ } } split /\s+/, $grant->data->{scope} || ''
        ],
        (
            $grant->data->{authorization_details}
            ? ( authorization_details => $grant->data->{authorization_details} )
            : ()
        ),
    };
    return $self->p->sendJSONresponse( $req, $body, code => 200 );
}

sub _grantDelete {
    my ( $self, $req, $grant, $rp ) = @_;
    my $grant_id = $grant->id;
    if ( $grant->remove ) {
        $self->logger->debug(
            "OIDCGrantManagement: revoked grant `$grant_id` for $rp");
    }
    else {
        $self->logger->error(
            "OIDCGrantManagement: failed to remove grant `$grant_id`: "
              . $grant->error );
        return $self->_jsonError( $req, 500, 'server_error',
            'Failed to remove grant' );
    }

    # Spec mandates 204 No Content on success.
    return $self->p->sendBinaryResponse( $req, '', code => 204 );
}

# ---------------------------------------------------------------------------
# Helpers

sub _loadGrant {
    my ( $self, $grant_id ) = @_;
    return undef unless $grant_id;
    return $self->oidc->getOpenIDConnectSession( $grant_id, &SESSION_KIND );
}

# Union of two `authorization_details` arrays, deduped by structural
# equality (cheap JSON-canonical comparison). Used by the `update`
# action so a fintech adding a second account doesn't lose the first one.
sub _mergeRar {
    my ( $existing, $new ) = @_;
    return $existing unless defined $new and ref($new) eq 'ARRAY';
    return $new
      unless defined $existing
      and ref($existing) eq 'ARRAY'
      and @$existing;

    my %seen;
    my @out;
    for my $entry ( @$existing, @$new ) {
        my $key = JSON->new->canonical->encode($entry);
        next if $seen{$key}++;
        push @out, $entry;
    }
    return \@out;
}

sub _jsonError {
    my ( $self, $req, $code, $error, $description ) = @_;
    return $self->p->sendJSONresponse(
        $req,
        {
            error => $error,
            ( $description ? ( error_description => $description ) : () ),
        },
        code => $code,
    );
}

1;
