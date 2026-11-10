package Lemonldap::NG::Portal::Plugins::OIDCCIBA;

use strict;
use Mouse;
use JSON qw(decode_json encode_json);
use Crypt::JWT qw(decode_jwt);
use Lemonldap::NG::Common::JWT qw(getJWTHeader);
use Lemonldap::NG::Common::UserAgent;
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
  PE_SENDRESPONSE
);

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

our $VERSION = '2.23.0';

# INTERFACE
use constant hook => {
    oidcGotTokenRequest  => 'handleCibaGrant',
    oidcGenerateMetadata => 'addCibaMetadata',
};

has ua => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        Lemonldap::NG::Common::UserAgent->new( $_[0]->{conf} );
    }
);

has path => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]->oidc->path;
    }
);

# Steps computing groups and macros of a user looked up without a session.
# LLNG <= 2.23 exposes Main::Run::groupsAndMacros(), which honours the
# `groupsBeforeMacros` option; that option was dropped upstream (#3482) and
# groups are now always computed first.
sub groupsAndMacros {
    my ($self) = @_;
    return $self->p->can('groupsAndMacros')
      ? $self->p->groupsAndMacros
      : qw(setGroups setMacros);
}

sub init {
    my ($self) = @_;

    return unless $self->SUPER::init;

    $self->oidc->can('addRouteFromConf')->(
        $self, 'Unauth',
        oidcServiceMetaDataCibaCallbackURI => 'authenticationCallback',
        oidcServiceMetaDataCibaURI         => 'backchannelAuthentication',
    );

    $self->oidc->can('addRouteFromConf')->(
        $self, 'Auth',
        oidcServiceMetaDataCibaURI => 'backchannelAuthenticationAuth',
    );

    return 1;
}

sub addCibaMetadata {
    my ( $self, $req, $metadata ) = @_;
    my $issuer = $metadata->{issuer};
    my $path   = $self->path . '/';
    $path = '/' . $path unless $issuer =~ /\/$/;
    my $baseUrl = $issuer . $path;

    push @{ $metadata->{grant_types_supported} },
      "urn:openid:params:grant-type:ciba";
    $metadata->{backchannel_authentication_endpoint} =
      $baseUrl . $self->conf->{oidcServiceMetaDataCibaURI};
    $metadata->{backchannel_token_delivery_modes_supported} =
      [ 'poll', 'ping' ];
    $metadata
      ->{backchannel_authentication_request_signing_alg_values_supported} =
      $metadata->{id_token_signing_alg_values_supported};
    $metadata->{backchannel_user_code_parameter_supported} = JSON::false;

    return PE_OK;
}

# POST /bc-authorize - Backchannel Authentication Request
# https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7
sub backchannelAuthentication {
    my ( $self, $req ) = @_;

    $self->logger->debug('CIBA backchannel authentication request received');

    my ( $rp, $authMethod ) =
      $self->oidc->checkEndPointAuthenticationCredentials($req);
    return $self->_cibaError( $req, 'invalid_client', 401 ) unless $rp;

    $self->logger->debug("CIBA request from RP: $rp");

    unless ( $self->conf->{oidcRPMetaDataOptions}->{$rp}
        ->{oidcRPMetaDataOptionsAllowCIBA} )
    {
        $self->userLogger->error("CIBA not allowed for RP $rp");
        return $self->_cibaError( $req, 'unauthorized_client', 400 );
    }

    # A public client cannot authenticate at the backchannel endpoint: anyone
    # who knows its client_id could push an authentication to any login_hint.
    if ( $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsPublic} ) {
        $self->userLogger->warn("CIBA: public client $rp refused");
        return $self->_cibaError( $req, 'unauthorized_client', 400 );
    }

    # Extract parameters
    my $scope                     = $req->param('scope') || '';
    my $login_hint                = $req->param('login_hint');
    my $id_token_hint             = $req->param('id_token_hint');
    my $login_hint_token          = $req->param('login_hint_token');
    my $binding_message           = $req->param('binding_message');
    my $user_code                 = $req->param('user_code');
    my $requested_expiry          = $req->param('requested_expiry');
    my $client_notification_token = $req->param('client_notification_token');
    my $acr_values                = $req->param('acr_values');

    # Validate scope
    unless ( $self->_hasOpenidScope($scope) ) {
        $self->logger->error('CIBA request missing openid scope');
        return $self->_cibaError( $req, 'invalid_scope', 400 );
    }

    # Validate hint (exactly one is required)
    my $hint_count =
      ( defined $login_hint       ? 1 : 0 ) +
      ( defined $id_token_hint    ? 1 : 0 ) +
      ( defined $login_hint_token ? 1 : 0 );

    if ( $hint_count == 0 ) {
        $self->logger->error('CIBA request missing user hint');
        return $self->_cibaError( $req, 'invalid_request', 400,
            'One of login_hint, id_token_hint, or login_hint_token is required'
        );
    }

    if ( $hint_count > 1 ) {
        $self->logger->error('CIBA request has multiple hints');
        return $self->_cibaError( $req, 'invalid_request', 400,
            'Only one hint parameter is allowed' );
    }

    # Resolve the user from the hint
    my ( $user, $user_info, $hint_error ) =
      $self->_resolveUserFromHint( $req, $rp, $login_hint, $id_token_hint,
        $login_hint_token );

    if ($hint_error) {
        $self->userLogger->warn("CIBA: invalid user hint ($hint_error)");
        return $self->_cibaError( $req, $hint_error, 400 );
    }

    unless ($user) {
        $self->userLogger->warn('CIBA: Could not resolve user from hint');
        return $self->_cibaError( $req, 'unknown_user_id', 400 );
    }

    $self->logger->debug("CIBA resolved user: $user");

    # The RP rule is evaluated once the user is known, before the pending
    # session is created.
    $req->userData($user_info);
    unless ( $self->_checkCibaRule( $req, $rp, $user_info ) ) {
        $self->userLogger->warn("CIBA: user $user refused by the RP rule");
        return $self->_cibaError( $req, 'access_denied', 403 );
    }

    # Resolve the scope now that the user (and their groups/macros) is known.
    # Only the result is stored in the CIBA session.
    $scope = $self->oidc->getScope( $req, $rp, $scope );
    unless ( $self->_hasOpenidScope($scope) ) {
        $self->logger->error('CIBA scope resolution removed openid');
        return $self->_cibaError( $req, 'invalid_scope', 400 );
    }

    # Get CIBA mode for this RP
    my $ciba_mode =
      $self->conf->{oidcRPMetaDataOptions}->{$rp}
      ->{oidcRPMetaDataOptionsCIBAMode}
      || 'poll';

    # For ping mode, client_notification_token is required
    if ( $ciba_mode eq 'ping' && !$client_notification_token ) {
        $self->logger->error(
            'CIBA ping mode requires client_notification_token');
        return $self->_cibaError( $req, 'invalid_request', 400,
            'client_notification_token required for ping mode' );
    }

    # Calculate expiration
    my $default_expiry = $self->conf->{oidcServiceCibaExpiration}    || 120;
    my $max_expiry     = $self->conf->{oidcServiceCibaMaxExpiration} || 300;
    my $expires_in     = $default_expiry;

    if ( defined $requested_expiry && $requested_expiry =~ /^\d+$/ ) {
        $expires_in = $requested_expiry;
        if ( $expires_in > $max_expiry ) {
            $expires_in = $max_expiry;
        }
    }

    # Create CIBA session (pending state)
    my $auth_req_id = $self->_createCibaSession(
        $req,
        {
            rp                        => $rp,
            scope                     => $scope,
            user                      => $user,
            user_info                 => $user_info,
            login_hint                => $login_hint,
            binding_message           => $binding_message,
            client_notification_token => $client_notification_token,
            acr_values                => $acr_values,
            status                    => 'pending',
            ciba_mode                 => $ciba_mode,
            expires_at                => time + $expires_in,
        }
    );

    unless ($auth_req_id) {
        $self->logger->error('CIBA: Failed to create CIBA session');
        return $self->_cibaError( $req, 'server_error', 500 );
    }

    $self->logger->debug("CIBA session created: $auth_req_id");

    # Call external authentication channel to notify user
    my $notified = $self->_notifyAuthenticationDevice(
        $req,
        {
            auth_req_id     => $auth_req_id,
            login_hint      => $login_hint,
            user            => $user,
            binding_message => $binding_message,
            scope           => $scope,
            rp              => $rp,
            acr_values      => $acr_values,
            expires_in      => $expires_in,
        }
    );

    unless ($notified) {

        # Delete the CIBA session if notification failed
        $self->_deleteCibaSession($auth_req_id);
        $self->logger->error('CIBA: Failed to notify authentication device');
        return $self->_cibaError( $req, 'access_denied', 400,
            'Failed to notify authentication device' );
    }

    $self->auditLog(
        $req,
        message => "CIBA request initiated for user $user by RP $rp",
        code    => 'CIBA_REQUEST_INITIATED',
        rp      => $rp,
        user    => $user,
    );

    # Return auth_req_id to client
    my $interval = $self->conf->{oidcServiceCibaInterval} || 5;

    return $self->p->sendJSONresponse(
        $req,
        {
            auth_req_id => $auth_req_id,
            expires_in  => $expires_in + 0,
            interval    => $interval + 0,
        }
    );
}

# POST /bc-authorize (authenticated) - Direct approval when user is already logged in
sub backchannelAuthenticationAuth {
    my ( $self, $req ) = @_;

    $self->logger->debug("CIBA backchannelAuthenticationAuth called");

    my $res = eval { $self->_backchannelAuthenticationAuthImpl($req) };
    if ($@) {
        $self->logger->error("CIBA auth error: $@");
        return $self->_cibaError( $req, 'server_error', 500 );
    }
    return $res;
}

sub _backchannelAuthenticationAuthImpl {
    my ( $self, $req ) = @_;

    my $user = $req->user;
    $self->logger->debug(
        "CIBA backchannel auth request from authenticated user: $user");

    # Verify OIDC issuer is available
    unless ( $self->oidc ) {
        $self->logger->error('OIDC issuer not available for CIBA');
        return $self->_cibaError( $req, 'server_error', 500 );
    }

    # Authenticate the client (RP)
    my ( $rp, $authMethod ) =
      $self->oidc->checkEndPointAuthenticationCredentials($req);
    return $self->_cibaError( $req, 'invalid_client', 401 ) unless $rp;

    # Verify that CIBA is enabled for this RP
    unless ( $self->conf->{oidcRPMetaDataOptions}->{$rp}
        ->{oidcRPMetaDataOptionsAllowCIBA} )
    {
        return $self->_cibaError( $req, 'unauthorized_client', 400 );
    }

    # See backchannelAuthentication(): a public client is not acceptable here.
    if ( $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsPublic} ) {
        $self->userLogger->warn("CIBA: public client $rp refused");
        return $self->_cibaError( $req, 'unauthorized_client', 400 );
    }

    my $scope      = $req->param('scope') || '';
    my $login_hint = $req->param('login_hint');

    unless ( $self->_hasOpenidScope($scope) ) {
        return $self->_cibaError( $req, 'invalid_scope', 400 );
    }

    unless ($login_hint) {
        return $self->_cibaError( $req, 'invalid_request', 400,
            'login_hint required' );
    }

    # Verify login_hint matches authenticated user
    unless ( $login_hint eq $user ) {
        $self->userLogger->warn(
"CIBA: login_hint ($login_hint) doesn't match authenticated user ($user)"
        );

        # Fall back to standard flow (notify external channel)
        return $self->_cibaError( $req, 'invalid_request', 403,
            'not the same user' );
    }

    # The RP rule is evaluated on the authenticated session before any token
    # is minted, as on /oauth2/authorize.
    unless ( $self->_checkCibaRule( $req, $rp, $req->userData ) ) {
        $self->userLogger->warn("CIBA: user $user refused by the RP rule");
        return $self->_cibaError( $req, 'access_denied', 403 );
    }

    # Resolve the scope now that the user is known; only the result is used.
    $scope = $self->oidc->getScope( $req, $rp, $scope );
    unless ( $self->_hasOpenidScope($scope) ) {
        $self->logger->error('CIBA scope resolution removed openid');
        return $self->_cibaError( $req, 'invalid_scope', 400 );
    }

    # 5. User matches - approve directly and generate tokens
    $self->logger->debug("CIBA: Direct approval for user $user");

    my $client_id =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};

    # Build session info from current user session
    my $sessionInfo = {
        %{ $req->userData },
        _auth          => 'CIBA',
        _scope         => $scope,
        _clientId      => $client_id,
        _clientConfKey => $rp,
    };

    # Generate access token
    my $access_token =
      $self->oidc->newAccessToken( $req, $rp, $scope, $sessionInfo, {} );

    unless ($access_token) {
        return $self->_cibaError( $req, 'server_error', 500 );
    }

    my $at_exp =
      $self->oidc->rpOptions->{$rp}
      ->{oidcRPMetaDataOptionsAccessTokenExpiration}
      || $self->conf->{oidcServiceAccessTokenExpiration};

    my $token_response = {
        access_token => $access_token,
        token_type   => 'Bearer',
        expires_in   => $at_exp + 0,
    };

    # Generate ID token
    if ( $self->_hasOpenidScope($scope) ) {
        my $id_token =
          $self->oidc->_generateIDToken( $req, $rp, $scope, $sessionInfo, 0,
            {} );
        $token_response->{id_token} = $id_token if $id_token;
    }

    # Generate refresh token if configured
    if ( $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsRefreshToken} ) {
        my $refreshTokenSession = $self->oidc->newRefreshToken(
            $rp,
            {
                %$sessionInfo,
                scope        => $scope,
                client_id    => $client_id,
                _session_uid => $sessionInfo->{_session_uid} || $user,
                grant_type   => 'urn:openid:params:grant-type:ciba',
            },
        );
        $token_response->{refresh_token} = $refreshTokenSession->id
          if $refreshTokenSession;
    }

    $self->auditLog(
        $req,
        message => "CIBA direct authentication for user $user",
        code    => 'CIBA_DIRECT_AUTH',
        rp      => $rp,
        user    => $user,
    );

    return $self->p->sendJSONresponse( $req, $token_response );
}

# POST /ciba/callback - Callback from external authentication channel
sub authenticationCallback {
    my ( $self, $req ) = @_;

    $self->logger->debug('CIBA callback received');

    # Validate the bearer token from external service
    my $auth_header = $req->env->{HTTP_AUTHORIZATION} || '';
    my ($token) = $auth_header =~ /^Bearer\s+(.+)$/i;

    my $expected_secret = $self->conf->{oidcServiceCibaCallbackSecret};

    unless ( $token && $expected_secret && $token eq $expected_secret ) {
        $self->logger->error('CIBA callback: Invalid or missing authorization');
        return $self->p->sendJSONresponse(
            $req,
            { error => 'unauthorized' },
            code => 401
        );
    }

    # Extract parameters from JSON body
    my $body;
    eval { $body = decode_json( $req->content ); };
    if ( $@ or ref $body ne 'HASH' ) {
        $self->logger->error('CIBA callback: Invalid JSON body: '
              . ( $@ || 'not an object' ) );
        return $self->p->sendJSONresponse(
            $req,
            { error => 'invalid_request', error_description => 'Invalid JSON' },
            code => 400
        );
    }

    my $auth_req_id = $body->{auth_req_id};
    my $status      = $body->{status};       # 'approved' or 'denied'
    my $auth_time   = $body->{auth_time};    # Authentication time (optional)

    unless ( defined $auth_req_id
        and !ref $auth_req_id
        and length $auth_req_id )
    {
        $self->logger->error('CIBA callback: Missing auth_req_id');
        return $self->p->sendJSONresponse(
            $req,
            { error => 'invalid_request' },
            code => 400
        );
    }

    unless ( $status && $status =~ /^(approved|denied)$/ ) {
        $self->logger->error('CIBA callback: Invalid status');
        return $self->p->sendJSONresponse(
            $req,
            { error => 'invalid_request' },
            code => 400
        );
    }

    # Retrieve CIBA session
    my $cibaSession = $self->_getCibaSession($auth_req_id);
    unless ($cibaSession) {
        $self->logger->error(
            "CIBA callback: Session not found for $auth_req_id");
        return $self->p->sendJSONresponse(
            $req,
            { error => 'invalid_auth_req_id' },
            code => 400
        );
    }

    # Check if session has expired
    if ( time > $cibaSession->{expires_at} ) {
        $self->logger->error('CIBA callback: Session has expired');
        $self->_deleteCibaSession($auth_req_id);
        return $self->p->sendJSONresponse(
            $req,
            { error => 'expired_token' },
            code => 400
        );
    }

    # Check session is still pending
    if ( $cibaSession->{status} ne 'pending' ) {
        $self->logger->error('CIBA callback: Session already processed');
        return $self->p->sendJSONresponse(
            $req,
            { error => 'invalid_request' },
            code => 400
        );
    }

    my $rp   = $cibaSession->{rp};
    my $user = $cibaSession->{user};

    if ( $status eq 'approved' ) {
        $self->logger->debug("CIBA: User $user approved authentication");

        # Update session with approved status. The callback only contributes a
        # plausible authentication time: `sub` and `acr` are not read later,
        # so a channel cannot claim them.
        $cibaSession->{status} = 'approved';
        my $valid_auth_time = $self->_validAuthTime($auth_time);
        $self->logger->warn(
            'CIBA callback: invalid auth_time, using current time')
          if defined $auth_time and !defined $valid_auth_time;
        $cibaSession->{auth_time} = $valid_auth_time // time;

        # Create user session for token generation
        my $session_id = $self->_createUserSessionForCiba( $req, $cibaSession );
        if ($session_id) {
            $cibaSession->{user_session_id} = $session_id;
        }
        else {
            $self->logger->error('CIBA: Failed to create user session');
            $cibaSession->{status} = 'denied';
            $cibaSession->{error}  = 'server_error';
        }

        $self->auditLog(
            $req,
            message => "CIBA authentication approved for user $user",
            code    => 'CIBA_APPROVED',
            rp      => $rp,
            user    => $user,
        );
    }
    else {
        $self->logger->debug("CIBA: User $user denied authentication");
        $cibaSession->{status} = 'denied';

        $self->auditLog(
            $req,
            message => "CIBA authentication denied for user $user",
            code    => 'CIBA_DENIED',
            rp      => $rp,
            user    => $user,
        );
    }

    # Update CIBA session
    $self->_updateCibaSession( $auth_req_id, $cibaSession );

    # If ping mode, notify the client
    if (   $cibaSession->{ciba_mode} eq 'ping'
        && $cibaSession->{client_notification_token} )
    {
        $self->_notifyClientPing( $req, $cibaSession );
    }

    return $self->p->sendJSONresponse( $req, { status => 'ok' } );
}

# Hook: grant_type=urn:openid:params:grant-type:ciba
sub handleCibaGrant {
    my ( $self, $req, $rp, $grant_type ) = @_;

    return PE_OK unless $grant_type eq 'urn:openid:params:grant-type:ciba';

    $self->logger->debug('CIBA grant type handler invoked');

    my $auth_req_id = $req->param('auth_req_id');
    unless ($auth_req_id) {
        $self->logger->error('CIBA grant: Missing auth_req_id');
        $req->response(
            $self->oidc->sendOIDCError( $req, 'invalid_request', 400 ) );
        return PE_SENDRESPONSE;
    }

    # Retrieve CIBA session
    my $cibaSession = $self->_getCibaSession($auth_req_id);
    unless ($cibaSession) {
        $self->logger->error("CIBA grant: Session not found for $auth_req_id");
        $req->response(
            $self->oidc->sendOIDCError( $req, 'invalid_grant', 400 ) );
        return PE_SENDRESPONSE;
    }

    # Verify RP matches
    if ( $cibaSession->{rp} ne $rp ) {
        $self->logger->error(
            "CIBA grant: RP mismatch - expected $cibaSession->{rp}, got $rp");
        $req->response(
            $self->oidc->sendOIDCError( $req, 'invalid_grant', 400 ) );
        return PE_SENDRESPONSE;
    }

    # Check if session has expired
    if ( time > $cibaSession->{expires_at} ) {
        $self->logger->error('CIBA grant: Session has expired');
        $self->_deleteCibaSession($auth_req_id);
        $req->response(
            $self->oidc->sendOIDCError( $req, 'expired_token', 400 ) );
        return PE_SENDRESPONSE;
    }

    # Check status
    if ( $cibaSession->{status} eq 'pending' ) {

        # Check polling interval (slow_down error) - only when pending
        my $interval   = $self->conf->{oidcServiceCibaInterval} || 5;
        my $last_poll  = $cibaSession->{last_poll_time}         || 0;
        my $now        = time;
        my $time_since = $now - $last_poll;

        if ( $last_poll > 0 && $time_since < $interval ) {
            $self->logger->debug(
"CIBA grant: Client polling too fast (${time_since}s < ${interval}s)"
            );
            $req->response(
                $self->oidc->sendOIDCError( $req, 'slow_down', 400 ) );
            return PE_SENDRESPONSE;
        }

        # Update last poll time
        $cibaSession->{last_poll_time} = $now;
        $self->_updateCibaSession( $auth_req_id, $cibaSession );

        $self->logger->debug('CIBA grant: Authorization pending');
        $req->response(
            $self->oidc->sendOIDCError( $req, 'authorization_pending', 400 ) );
        return PE_SENDRESPONSE;
    }

    if ( $cibaSession->{status} eq 'denied' ) {
        $self->logger->debug('CIBA grant: Access denied by user');
        $self->_deleteCibaSession($auth_req_id);
        $req->response(
            $self->oidc->sendOIDCError( $req, 'access_denied', 400 ) );
        return PE_SENDRESPONSE;
    }

    # Status = approved: generate tokens
    if ( $cibaSession->{status} eq 'approved' ) {
        $self->logger->debug('CIBA grant: Generating tokens');

        my $user_session_id = $cibaSession->{user_session_id};
        unless ($user_session_id) {
            $self->logger->error('CIBA grant: No user session available');
            $req->response(
                $self->oidc->sendOIDCError( $req, 'server_error', 500 ) );
            return PE_SENDRESPONSE;
        }

        # Get user session
        my $session =
          $self->p->getApacheSession( $user_session_id, kind => 'SSO' );
        unless ($session) {
            $self->logger->error('CIBA grant: User session not found');
            $self->_deleteCibaSession($auth_req_id);
            $req->response(
                $self->oidc->sendOIDCError( $req, 'invalid_grant', 400 ) );
            return PE_SENDRESPONSE;
        }

        my $sessionInfo = $session->data;
        my $scope       = $cibaSession->{scope};
        my $client_id =
          $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};

        # Re-evaluate the RP rule at issuance: the session could have changed
        # between the request and the approval.
        unless ( $self->_checkCibaRule( $req, $rp, $sessionInfo ) ) {
            $self->userLogger->warn(
                'CIBA grant: user refused by the RP rule');
            $req->response(
                $self->oidc->sendOIDCError( $req, 'access_denied', 403 ) );
            return PE_SENDRESPONSE;
        }

        # The scope was resolved at /bc-authorize; keep the openid invariant.
        unless ( $self->_hasOpenidScope($scope) ) {
            $req->response(
                $self->oidc->sendOIDCError( $req, 'invalid_scope', 400 ) );
            return PE_SENDRESPONSE;
        }

        # Create access token
        my $access_token = $self->oidc->newAccessToken(
            $req, $rp, $scope,
            $sessionInfo,
            {
                user_session_id => $user_session_id,
            }
        );

        unless ($access_token) {
            $self->logger->error('CIBA grant: Failed to create access token');
            $req->response(
                $self->oidc->sendOIDCError( $req, 'server_error', 500 ) );
            return PE_SENDRESPONSE;
        }

        # Generate token response
        my $at_exp =
          $self->oidc->rpOptions->{$rp}
          ->{oidcRPMetaDataOptionsAccessTokenExpiration}
          || $self->conf->{oidcServiceAccessTokenExpiration};

        my $token_response = {
            access_token => $access_token,
            token_type   => 'Bearer',
            expires_in   => $at_exp + 0,
        };

        # Generate ID token if openid scope
        if ( $self->_hasOpenidScope($scope) ) {

            # Override auth_time in session if provided by CIBA
            my $session_for_idtoken = {%$sessionInfo};
            $session_for_idtoken->{_lastAuthnUTime} = $cibaSession->{auth_time}
              if $cibaSession->{auth_time};

            my $id_token = $self->oidc->_generateIDToken(
                $req, $rp, $scope,
                $session_for_idtoken,
                0,     # Don't release user claims in ID token
                {},    # No extra claims for now
            );

            if ($id_token) {
                $token_response->{id_token} = $id_token;
            }
        }

        # Add refresh token if configured
        if (
            $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsRefreshToken} )
        {
            my $refreshTokenSession = $self->oidc->newRefreshToken(
                $rp,
                {
                    %$sessionInfo,
                    scope        => $scope,
                    client_id    => $client_id,
                    _session_uid => $sessionInfo->{_session_uid}
                      || $cibaSession->{user},
                    grant_type => 'urn:openid:params:grant-type:ciba',
                },
            );

            if ($refreshTokenSession) {
                $token_response->{refresh_token} = $refreshTokenSession->id;
            }
        }

        $self->auditLog(
            $req,
            message => "CIBA tokens issued for user $cibaSession->{user}",
            code    => 'CIBA_TOKENS_ISSUED',
            rp      => $rp,
            user    => $cibaSession->{user},
        );

        # Delete CIBA session (tokens have been issued)
        $self->_deleteCibaSession($auth_req_id);

        $req->response( $self->p->sendJSONresponse( $req, $token_response ) );
        return PE_SENDRESPONSE;
    }

    # Unknown status
    $self->logger->error("CIBA grant: Unknown status $cibaSession->{status}");
    $req->response( $self->oidc->sendOIDCError( $req, 'server_error', 500 ) );
    return PE_SENDRESPONSE;
}

# Private helper methods

sub _cibaError {
    my ( $self, $req, $error, $code, $description ) = @_;

    $code ||= 400;

    my $response = { error => $error };
    $response->{error_description} = $description if $description;

    return $self->p->sendJSONresponse( $req, $response, code => $code );
}

# CIBA Core allows the authentication channel to return auth_time. Keep only
# a plausible integer value (not in the future beyond a small clock skew);
# anything else falls back to the current time.
sub _validAuthTime {
    my ( $self, $value ) = @_;
    return undef unless defined $value && !ref $value;
    return undef unless $value =~ /\A[0-9]+\z/;
    my $auth_time = $value + 0;
    return undef if $auth_time > time + 30;
    return $auth_time;
}

# Scope values are space-delimited tokens: `-openid` and `my-openid` are not
# the `openid` scope.
sub _hasOpenidScope {
    my ( $self, $scope ) = @_;
    return 0 unless defined $scope && !ref $scope;
    return scalar grep { $_ eq 'openid' } split /\s+/, $scope;
}

# Evaluate the per-RP access rule once the user is known. Core does this on
# the authorization endpoint and the other grants; CIBA never did.
sub _checkCibaRule {
    my ( $self, $req, $rp, $data ) = @_;
    my $rule = $self->oidc->rpRules->{$rp} or return 1;
    return $rule->( $req, { %$data, _oidc_grant_type => 'ciba' } ) ? 1 : 0;
}

sub _resolveUserFromHint {
    my ( $self, $req, $rp, $login_hint, $id_token_hint, $login_hint_token ) =
      @_;

    # Handle login_hint (most common). The value is a local user identifier:
    # resolve it through the configured backends instead of trusting it.
    if ( defined $login_hint ) {
        $self->logger->debug(
            "CIBA: Resolving user from login_hint: $login_hint");

        my $sessionInfo = $self->_lookupUser( $req, $login_hint );
        return ( undef, undef, 'unknown_user_id' ) unless $sessionInfo;
        return ( $login_hint, $sessionInfo );
    }

    # Handle id_token_hint. It must be an ID token issued by this OP, with a
    # valid signature, our issuer and the requesting client as audience.
    elsif ( defined $id_token_hint ) {
        $self->logger->debug('CIBA: Resolving user from id_token_hint');

        my $claims = $self->_verifyIdTokenHint( $req, $rp, $id_token_hint );
        return ( undef, undef, 'invalid_request' ) unless $claims;

        my $sub = $claims->{sub};
        return ( undef, undef, 'invalid_request' )
          unless defined $sub && !ref $sub && length $sub;

        # LLNG computes sub from the RP user-ID attribute. Only use it as a
        # login when that attribute is the local login attribute and is not
        # an RP macro; otherwise we cannot map it back safely.
        unless ( $self->_subIsLogin($rp) ) {
            $self->logger->error(
                'CIBA: id_token_hint sub cannot be mapped back to a login');
            return ( undef, undef, 'invalid_request' );
        }

        my $sessionInfo = $self->_lookupUser( $req, $sub );
        return ( undef, undef, 'unknown_user_id' ) unless $sessionInfo;
        return ( $sub, $sessionInfo );
    }

    # Handle login_hint_token. CIBA Core leaves its format to the deployment,
    # and this plugin has no verifier configuration for it: fail closed.
    elsif ( defined $login_hint_token ) {
        $self->logger->debug(
            'CIBA: login_hint_token verifier is not configured');
        return ( undef, undef, 'invalid_request' );
    }

    return ( undef, undef, 'invalid_request' );
}

sub _subIsLogin {
    my ( $self, $rp ) = @_;
    my $whatToTrace = $self->conf->{whatToTrace} || 'uid';
    my $userIdAttr =
         $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsUserIDAttr}
      || $whatToTrace;
    return 0 unless $userIdAttr eq $whatToTrace;

    my $macros = $self->oidc->rpMacros->{$rp} || {};
    return 0 if $macros->{$userIdAttr};
    return 1;
}

# Resolve a user through the local user backends. There is no interactive
# authentication here: the hint already names the user, we only need this
# server's own view of them.
sub _lookupUser {
    my ( $self, $req, $user ) = @_;

    return unless defined $user && !ref $user && length $user;

    $req->user($user);
    $req->sessionInfo( {} );
    if ( my $choice = $self->conf->{oidcServiceCibaChoice} ) {
        $req->data->{_authChoice} = $choice;
    }
    $req->steps( [
            'getUser',              'setSessionInfo',
            $self->groupsAndMacros, 'setLocalGroups'
        ]
    );

    my $error = $self->p->process($req);
    if ( $error != PE_OK ) {
        $self->logger->info("CIBA: user '$user' not found (error: $error)");
        return;
    }

    my $sessionInfo = $req->sessionInfo || {};
    $sessionInfo->{_utime} ||= time;
    return $sessionInfo;
}

# Verify an id_token_hint as an ID token produced by this OP for $rp.
sub _verifyIdTokenHint {
    my ( $self, $req, $rp, $jwt ) = @_;

    return unless defined $jwt && !ref $jwt && length $jwt;

    my $header = eval { getJWTHeader($jwt) };
    return unless $header && ref $header eq 'HASH';

    my $alg = $header->{alg};
    return unless defined $alg && !ref $alg && $alg ne 'none';

    # Only an asymmetric signature can prove that this OP issued the token.
    # With an HS algorithm the client shares the secret and could forge it,
    # so such a hint is no better than login_hint.
    return if $alg =~ /^HS/;

    my @keys = $self->_idTokenVerificationKeys($rp);
    return unless @keys;

    my $claims;
    for my $key (@keys) {
        $claims = eval { decode_jwt( token => $jwt, key => \$key ) };
        last if $claims;
    }

    return unless $claims && ref $claims eq 'HASH';

    my $issuer = $self->oidc->get_issuer($req);
    unless ( $issuer
        && defined $claims->{iss}
        && !ref $claims->{iss}
        && $claims->{iss} eq $issuer )
    {
        return;
    }

    my $aud = $claims->{aud};
    my @aud =
      ref $aud eq 'ARRAY' ? @$aud : ( defined $aud ? ($aud) : () );
    my $client_id =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};
    unless ( defined $client_id
        && grep { defined $_ && !ref $_ && $_ eq $client_id } @aud )
    {
        return;
    }

    return $claims;
}

sub _idTokenVerificationKeys {
    my ( $self, $rp ) = @_;

    my $configured =
         $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsSigningKey}
      || $self->conf->{oidcServiceSignatureKey};
    my @ids = grep { length } split /\s*,\s*/, ( $configured // '' );
    push @ids, qw(default-oidc-sig old-oidc-sig new-oidc-sig);

    my ( @keys, %seen );
    for my $id (@ids) {
        my $key = $self->oidc->get_public_key($id);
        next unless $key && $key->{public};
        next if $seen{ $key->{public} }++;
        push @keys, $key->{public};
    }

    return @keys;
}

sub _createCibaSession {
    my ( $self, $req, $info ) = @_;

    my $ttl = $self->conf->{oidcServiceCibaMaxExpiration} || 300;

    my $session = $self->oidc->getOpenIDConnectSession(
        undef,
        'ciba',
        ttl  => $ttl,
        info => $info,
    );

    return undef unless $session;
    return $session->id;
}

sub _getCibaSession {
    my ( $self, $auth_req_id ) = @_;

    my $session = $self->oidc->getOpenIDConnectSession( $auth_req_id, 'ciba' );
    return undef unless $session;

    return $session->data;
}

sub _updateCibaSession {
    my ( $self, $auth_req_id, $data ) = @_;

    my $session = $self->oidc->getOpenIDConnectSession( $auth_req_id, 'ciba' );
    return 0 unless $session;

    # Update session data
    foreach my $key ( keys %$data ) {
        next if $key eq '_type' || $key eq '_utime';
        $session->update( { $key => $data->{$key} } );
    }

    return 1;
}

sub _deleteCibaSession {
    my ( $self, $auth_req_id ) = @_;

    my $session = $self->oidc->getOpenIDConnectSession( $auth_req_id, 'ciba' );
    return 0 unless $session;

    $session->remove;
    return 1;
}

sub _notifyAuthenticationDevice {
    my ( $self, $req, $params ) = @_;

    my $url = $self->conf->{oidcServiceCibaAuthenticationChannelUrl};
    unless ($url) {
        $self->logger->error('CIBA: No authentication channel URL configured');
        return 0;
    }

    my $secret = $self->conf->{oidcServiceCibaAuthenticationChannelSecret};

    my @headers = ( 'Content-Type' => 'application/json' );
    if ($secret) {
        push @headers, 'Authorization' => "Bearer $secret";
    }

    my $payload = encode_json($params);

    $self->logger->debug("CIBA: Notifying authentication channel at $url");

    my $response = $self->ua->post( $url, @headers, Content => $payload );

    if ( $response->is_success ) {
        $self->logger->debug(
            'CIBA: Authentication channel notified successfully');
        return 1;
    }
    else {
        $self->logger->error(
            'CIBA: Failed to notify authentication channel: '
              . $response->status_line );
        return 0;
    }
}

sub _notifyClientPing {
    my ( $self, $req, $cibaSession ) = @_;

    my $rp = $cibaSession->{rp};
    my $endpoint =
      $self->conf->{oidcRPMetaDataOptions}->{$rp}
      ->{oidcRPMetaDataOptionsCIBANotificationEndpoint};

    unless ($endpoint) {
        $self->logger->error(
            "CIBA ping: No notification endpoint configured for RP $rp");
        return 0;
    }

    my $token = $cibaSession->{client_notification_token};

    my @headers = (
        'Content-Type'  => 'application/json',
        'Authorization' => "Bearer $token",
    );

    my $payload = encode_json( { auth_req_id => $cibaSession->{_session_id} } );

    $self->logger->debug("CIBA: Sending ping notification to $endpoint");

    my $response = $self->ua->post( $endpoint, @headers, Content => $payload );

    if ( $response->is_success ) {
        $self->logger->debug('CIBA: Ping notification sent successfully');
        return 1;
    }
    else {
        $self->logger->error( 'CIBA: Failed to send ping notification: '
              . $response->status_line );
        return 0;
    }
}

# Create user session for CIBA token generation
sub _createUserSessionForCiba {
    my ( $self, $req, $cibaSession ) = @_;

    my $user      = $cibaSession->{user};
    my $rp        = $cibaSession->{rp};
    my $user_info = $cibaSession->{user_info} || {};

    # Build session info from the backend lookup, then set the CIBA fields
    # last so that they cannot be overridden by user attributes.
    my $sessionInfo = {
        %$user_info,
        $self->conf->{whatToTrace} => $user_info->{ $self->conf->{whatToTrace} }
          // $user,
        _user       => $user,
        _utime      => time,
        _auth       => 'CIBA',
        _authChoice => 'CIBA',
        _scope      => $cibaSession->{scope},
        _clientId   =>
          $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID},
        _clientConfKey => $rp,
    };

    # Create the session
    my $session =
      $self->p->getApacheSession( undef, info => $sessionInfo, kind => 'SSO' );
    unless ($session) {
        $self->logger->error('CIBA: Failed to create Apache session');
        return undef;
    }

    $self->logger->debug( 'CIBA: Created user session ' . $session->id );
    return $session->id;
}

1;
