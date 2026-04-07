package Lemonldap::NG::Portal::Plugins::OIDCDeviceAuthorization;

# OAuth 2.0 Device Authorization Grant - RFC 8628
# https://datatracker.ietf.org/doc/html/rfc8628
#
# With PKCE extension (RFC 7636) for additional security

use strict;
use Mouse;
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
  PE_SENDRESPONSE
  PE_NOTOKEN
  PE_TOKENEXPIRED
  PE_UNAUTHORIZEDPARTNER
);
use JSON qw(from_json to_json);
use Crypt::URandom;
use Digest::SHA qw(sha256_hex);

our $VERSION = '2.23.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

use constant hook => {

    # Hook called by OpenIDConnect.pm token method before grant type dispatch
    oidcGotTokenRequest => 'deviceCodeGrantHook',
};

# Character set for user_code (RFC 8628 section 6.1)
# Base-20 without vowels to avoid offensive words, easy to type on mobile
use constant USER_CODE_CHARS => 'BCDFGHJKLMNPQRSTVWXZ';

# Session kind for device authorization storage
use constant sessionKind => 'DEVA';

# Lazy access to CrowdSecAgent plugin (optional, for abuse reporting)
has crowdsec => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]
          ->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::CrowdSecAgent'};
    }
);

# One-time token for CSRF protection
has ott => (
    is      => 'rw',
    lazy    => 1,
    default => sub {
        my $ott =
          $_[0]->{p}->loadModule('Lemonldap::NG::Portal::Lib::OneTimeToken');
        $ott->timeout( $_[0]->conf->{formTimeout} );
        return $ott;
    }
);

# INITIALIZATION

sub init {
    my ($self) = @_;

    return unless $self->SUPER::init;

    # Device Authorization endpoint (RFC 8628 section 3.1)
    # POST /oauth2/device - for devices to request authorization
    my $oidc_path = $self->conf->{issuerDBOpenIDConnectPath} || '^/oauth2/';
    $oidc_path =~ s/^.*?(\w+).*?$/$1/;    # Extract path name (e.g., "oauth2")
    $self->addUnauthRoute(
        $oidc_path => { 'device' => 'deviceAuthorizationEndpoint' },
        ['POST']
      )

      # Duplication in case of virtual device inside the browser
      ->addAuthRoute(
        $oidc_path => { 'device' => 'deviceAuthorizationEndpoint' },
        ['POST']
      )

      # Device verification endpoint (for users) - /device
      ->addAuthRouteWithRedirect(
        device => 'displayVerification',
        ['GET']
      )->addAuthRoute(
        device => 'submitVerification',
        ['POST']
      );

    # Warn if CrowdSec is not configured (RFC 8628 recommends IP-based lockout)
    # Check config rather than loadedModules since init order is not guaranteed
    unless ($self->conf->{crowdsec}
        and $self->conf->{crowdsecAgent} )
    {
        $self->logger->warn(
"CrowdSecAgent plugin not configured. RFC 8628 recommends IP-based rate limiting for device authorization. Consider enabling CrowdSec for better security."
        );
    }

    $self->logger->debug("Device Authorization Grant (RFC 8628) initialized");
    return 1;
}

# Device Authorization endpoint (RFC 8628 section 3.1)
# Called directly via route POST /oauth2/device
sub deviceAuthorizationEndpoint {
    my ( $self, $req ) = @_;

    $self->logger->debug("Device Authorization endpoint called");

    # Client authentication: try full credentials first, fall back to
    # client_id only for public clients
    my $client_authenticated = 0;
    my ( $rp, $auth_method ) =
      $self->oidc->checkEndPointAuthenticationCredentials($req);

    if ($rp) {

        # "none" means only client_id was provided (no real authentication)
        $client_authenticated = 1
          if ( $auth_method && $auth_method ne 'none' );
    }
    else {
        # Fall back to client_id for public clients
        my $client_id = $req->param('client_id');
        unless ($client_id) {
            return $self->_sendDeviceError( $req, 'invalid_request',
                'client_id is required' );
        }

        $rp = $self->oidc->getRP($client_id);
        unless ($rp) {
            return $self->_sendDeviceError( $req, 'invalid_client' );
        }

        # Only public clients may skip client authentication
        unless ( $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsPublic} )
        {
            $self->logger->warn(
                "Confidential client $client_id must authenticate");
            return $self->_sendDeviceError( $req, 'invalid_client',
                'Client authentication required' );
        }
    }

    my $client_id =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};

    # Check if this RP allows device authorization grant
    unless ( $self->oidc->rpOptions->{$rp}
        ->{oidcRPMetaDataOptionsAllowDeviceAuthorization} )
    {
        $self->logger->warn(
            "Device authorization grant not allowed for RP $rp");
        return $self->_sendDeviceError( $req, 'unauthorized_client' );
    }

    # Get requested scope
    my $scope = $req->param('scope') || 'openid';

    # PKCE support (RFC 7636)
    my $code_challenge        = $req->param('code_challenge');
    my $code_challenge_method = $req->param('code_challenge_method') || 'plain';

    # Check if PKCE is required for this RP
    # requirePKCE=1: always required
    # requirePKCE=2: required only if client did not authenticate
    my $require_pkce =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsRequirePKCE} || 0;
    if ( $require_pkce == 1
        or ( $require_pkce == 2 and !$client_authenticated ) )
    {
        unless ($code_challenge) {
            $self->logger->warn(
                "PKCE required but no code_challenge provided for RP $rp");
            return $self->_sendDeviceError( $req, 'invalid_request',
                'code_challenge is required' );
        }
    }

    # Validate code_challenge_method if PKCE is used
    if ($code_challenge) {
        unless ( $code_challenge_method eq 'plain'
            or $code_challenge_method eq 'S256' )
        {
            $self->logger->warn(
                "Invalid code_challenge_method: $code_challenge_method");
            return $self->_sendDeviceError( $req, 'invalid_request',
                'code_challenge_method must be plain or S256' );
        }
        $self->logger->debug(
"PKCE enabled for device authorization (method=$code_challenge_method)"
        );
    }

    # Generate device_code (secret, used for polling)
    my $device_code = $self->_generateDeviceCode();

    # Store device authorization request
    my $expiration =
      $self->conf->{oidcServiceDeviceAuthorizationExpiration} || 600;
    my $interval =
      $self->conf->{oidcServiceDeviceAuthorizationPollingInterval} || 5;

    # Generate user_code with collision detection
    # Retry up to 10 times if collision occurs
    my $user_code;
    my $user_code_hash;
    my $max_retries = 10;

    for my $attempt ( 1 .. $max_retries ) {
        $user_code      = $self->_generateUserCode();
        $user_code_hash = sha256_hex($user_code);

        # Check if this user_code already exists
        my $existing = $self->p->getApacheSession(
            $user_code_hash,
            kind   => sessionKind,
            noInfo => 1,
        );

        if ( !$existing ) {

            # No collision, we can use this user_code
            last;
        }

        # Check if the existing session is expired
        if ( time() > ( $existing->data->{expires_at} || 0 ) ) {

            # Expired, remove it and use this user_code
            $existing->remove;
            last;
        }

        $self->logger->debug(
            "User code collision detected (attempt $attempt), regenerating");

        if ( $attempt == $max_retries ) {
            $self->logger->error(
"Failed to generate unique user_code after $max_retries attempts"
            );
            return $self->_sendDeviceError( $req, 'server_error' );
        }
    }

    # Create session with device_code hash as ID (for polling lookup)
    my $device_code_hash = sha256_hex($device_code);

    my $session_data = {
        _type          => 'deviceauth',
        _utime         => time() - $self->conf->{timeout} + $expiration,
        user_code      => $user_code,
        client_id      => $client_id,
        rp             => $rp,
        scope          => $scope,
        status         => 'pending',              # pending, approved, denied
        created_at     => time(),
        expires_at     => time() + $expiration,
        code_challenge => $code_challenge,
        code_challenge_method => $code_challenge_method,
    };

    # Store the device authorization using getApacheSession with fixed ID
    my $session = $self->p->getApacheSession(
        $device_code_hash,
        kind      => sessionKind,
        info      => $session_data,
        force     => 1,
        hashStore => 0,
    );

    unless ( $session && $session->id ) {
        $self->logger->error("Failed to create device authorization session");
        return $self->_sendDeviceError( $req, 'server_error' );
    }

    # Create session indexed by user_code for verification lookup
    my $user_code_session = $self->p->getApacheSession(
        $user_code_hash,
        kind => sessionKind,
        info => {
            _type            => 'deviceauth_usercode',
            _utime           => time() - $self->conf->{timeout} + $expiration,
            device_code_hash => $device_code_hash,
            user_code        => $user_code,
            expires_at       => time() + $expiration,
        },
        force     => 1,
        hashStore => 0,
    );

    unless ( $user_code_session && $user_code_session->id ) {
        $self->logger->error("Failed to create user_code lookup session");

        # Clean up the device_code session
        $session->remove;
        return $self->_sendDeviceError( $req, 'server_error' );
    }

    # Build verification URI
    my $portal           = $self->p->HANDLER->tsv->{portal}->();
    my $verification_uri = "$portal/device";
    my $formatted_code   = $self->_formatUserCode($user_code);
    my $verification_uri_complete =
      "$portal/device?user_code=" . ( $user_code =~ s/-//gr );

    # RFC 8628 section 3.2 - Device Authorization Response
    my $response = {
        device_code               => $device_code,
        user_code                 => $formatted_code,
        verification_uri          => $verification_uri,
        verification_uri_complete => $verification_uri_complete,
        expires_in                => $expiration + 0,
        interval                  => $interval + 0,
    };

    $self->logger->debug(
        "Device authorization created: user_code=$user_code, client=$client_id"
    );
    $self->userLogger->info(
        "Device authorization initiated for client $client_id");

    $self->auditLog(
        $req,
        code      => "ISSUER_OIDC_DEVICE_AUTH_INITIATED",
        rp        => $rp,
        user_code => $user_code,
        message   => "Device authorization initiated for RP $rp",
    );

    return $self->p->sendJSONresponse( $req, $response );
}

# HOOK: Token endpoint handler for device_code grant
# Called by OpenIDConnect.pm via processHook('oidcGotTokenRequest')
sub deviceCodeGrantHook {
    my ( $self, $req, $rp, $grant_type ) = @_;

    return PE_OK
      unless $grant_type eq 'urn:ietf:params:oauth:grant-type:device_code';

    $self->logger->debug("Device code grant hook called for RP $rp");

    my $device_code = $req->param('device_code');
    my $client_id   = $req->param('client_id')
      || $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};

    unless ($device_code) {
        return $self->_sendTokenError( $req, 'invalid_request',
            'device_code is required' );
    }

    # Check if this RP allows device authorization grant
    unless ( $self->oidc->rpOptions->{$rp}
        ->{oidcRPMetaDataOptionsAllowDeviceAuthorization} )
    {
        $self->logger->warn(
            "Device authorization grant not allowed for RP $rp");
        return $self->_sendTokenError( $req, 'unauthorized_client' );
    }

    # Find the device authorization
    my $device_auth = $self->_findByDeviceCode($device_code);

    unless ($device_auth) {

        # Token expired or invalid
        return $self->_sendTokenError( $req, 'expired_token' );
    }

    # Verify RP matches
    if ( $device_auth->{rp} ne $rp ) {
        $self->logger->warn( "RP mismatch in device_code grant: expected "
              . $device_auth->{rp}
              . ", got $rp" );
        return $self->_sendTokenError( $req, 'invalid_grant' );
    }

    # Check authorization status
    my $status = $device_auth->{status} || 'pending';

    if ( $status eq 'pending' ) {

        # RFC 8628 section 3.5 - Rate limiting with slow_down
        # Use poll count approach which is more resilient to race conditions
        my $interval =
          $self->conf->{oidcServiceDeviceAuthorizationPollingInterval} || 5;
        my $created_at = $device_auth->{created_at} || time();
        my $poll_count = ( $device_auth->{poll_count} || 0 ) + 1;
        my $now        = time();

        # Calculate maximum expected polls based on elapsed time
        my $elapsed          = $now - $created_at;
        my $max_expected     = int( $elapsed / $interval ) + 1;
        my $slow_down_margin = $device_auth->{slow_down_count} || 0;

        # If client has polled more than expected, return slow_down
        # Each slow_down increases the effective interval
        my $effective_max =
          int( $elapsed / ( $interval + $slow_down_margin * 5 ) ) + 1;

        if ( $poll_count > $effective_max + 1 ) {

            # Increment slow_down counter (increases effective interval)
            $self->_updateDeviceAuthStatus(
                $device_auth,
                'pending',
                {
                    poll_count      => $poll_count,
                    slow_down_count => $slow_down_margin + 1,
                }
            );
            $self->logger->debug(
"Client polling too fast (poll $poll_count, max $effective_max), returning slow_down"
            );
            return $self->_sendTokenError( $req, 'slow_down' );
        }

        # Update poll count
        $self->_updateDeviceAuthStatus( $device_auth, 'pending',
            { poll_count => $poll_count, } );

        # RFC 8628 section 3.5 - authorization_pending
        return $self->_sendTokenError( $req, 'authorization_pending' );
    }
    elsif ( $status eq 'denied' ) {

        # RFC 8628 section 3.5 - access_denied
        $self->_deleteDeviceAuth($device_auth);
        return $self->_sendTokenError( $req, 'access_denied' );
    }
    elsif ( $status eq 'approved' ) {

        # Generate tokens!
        return $self->_generateTokens( $req, $device_auth, $rp );
    }
    else {
        $self->logger->error("Unknown device auth status: $status");
        return $self->_sendTokenError( $req, 'server_error' );
    }
}

# DEVICE VERIFICATION PAGE (for authenticated users)
sub displayVerification {
    my ( $self, $req ) = @_;

    $self->logger->debug("Display device verification page");

    # Pre-fill user_code if provided in URL
    my $user_code = $req->param('user_code') || '';
    $user_code =~ s/[^A-Z0-9]//gi;    # Clean up

    # Create CSRF token
    my $token = $self->ott->createToken();

    # Set template parameters
    $req->data->{activeTimer} = 0;
    $req->{user_code} = $user_code;

    return $self->p->sendHtml(
        $req, 'device',
        params => {
            USER_CODE => $user_code,
            TOKEN     => $token,
            MSG       => '',
        }
    );
}

# DEVICE VERIFICATION SUBMIT
sub submitVerification {
    my ( $self, $req ) = @_;

    $self->logger->debug("Device verification submitted");

    # Verify CSRF token
    my $token = $req->param('token');
    unless ($token) {
        $self->userLogger->error('Device verification called without token');
        return $self->p->do( $req, [ sub { PE_NOTOKEN } ] );
    }
    unless ( $self->ott->getToken($token) ) {
        $self->userLogger->error(
            'Device verification called with invalid/expired token');
        return $self->p->do( $req, [ sub { PE_TOKENEXPIRED } ] );
    }

    my $user_code = $req->param('user_code') || '';
    $user_code =~ s/[^A-Z0-9]//gi;    # Remove formatting (dashes, spaces)
    $user_code = uc($user_code);

    unless ( $user_code && length($user_code) >= 6 ) {
        return $self->_showVerificationError( $req, 'invalidUserCode' );
    }

    # Find the device authorization by user_code
    my $device_auth = $self->_findByUserCode($user_code);
    unless ($device_auth) {
        $self->logger->info("Invalid or expired user_code: $user_code");

        # Report to CrowdSec if available (potential bruteforce)
        $self->_reportInvalidUserCode( $req, $user_code );

        my $user = $req->userData->{ $self->conf->{whatToTrace} };
        $self->auditLog(
            $req,
            code      => "ISSUER_OIDC_DEVICE_AUTH_INVALID_CODE",
            user_code => $user_code,
            user      => $user,
            message   => "Invalid or expired user_code submitted by $user",
        );

        return $self->_showVerificationError( $req, 'invalidUserCode' );
    }

    # Check if already processed
    if ( $device_auth->{status} ne 'pending' ) {
        $self->logger->info("User code already processed: $user_code");
        return $self->_showVerificationError( $req, 'codeAlreadyUsed' );
    }

    # Check RP-specific device authorization rule (boolOrExpr)
    my $rp            = $device_auth->{rp};
    my $rp_activation = $self->oidc->rpOptions->{$rp}
      ->{oidcRPMetaDataOptionsAllowDeviceAuthorization};
    if ( $rp_activation && $rp_activation ne '1' ) {
        my $rule =
          $self->p->buildRule( $rp_activation, 'deviceAuthorizationRule' );
        unless ( $rule && $rule->( $req, $req->userData ) ) {
            my $user = $req->userData->{ $self->conf->{whatToTrace} };
            $self->userLogger->warn(
                "User $user not authorized to register devices for RP $rp");
            $self->auditLog(
                $req,
                code      => "ISSUER_OIDC_DEVICE_AUTH_RULE_DENIED",
                rp        => $rp,
                user_code => $user_code,
                user      => $user,
                message   =>
                  "Device authorization denied by rule for $user on RP $rp",
            );
            return $self->p->do( $req, [ sub { PE_UNAUTHORIZEDPARTNER } ] );
        }
    }

    # Check action (approve or deny)
    my $action = $req->param('action') || 'approve';

    if ( $action eq 'deny' ) {

        # User denied the authorization
        $self->_updateDeviceAuthStatus( $device_auth, 'denied' );
        my $user = $req->userData->{ $self->conf->{whatToTrace} };
        $self->userLogger->notice(
            "Device authorization denied by user $user for client "
              . $device_auth->{client_id} );

        $self->auditLog(
            $req,
            code      => "ISSUER_OIDC_DEVICE_AUTH_DENIED",
            rp        => $device_auth->{rp},
            user_code => $device_auth->{user_code},
            user      => $user,
            message   =>
              "Device authorization denied by $user for RP $device_auth->{rp}",
        );

        return $self->p->sendHtml(
            $req, 'device',
            params => {
                DEVICE_DENIED => 1,
                MSG           => 'deviceDenied',
            }
        );
    }

    # Approve the authorization
    # Store user info for token generation
    my $user_session_id = $req->id || $req->userData->{_session_id};
    my $user            = $req->userData->{ $self->conf->{whatToTrace} };

    $self->_updateDeviceAuthStatus(
        $device_auth,
        'approved',
        {
            user_session_id => $user_session_id,
            user            => $user,
            approved_at     => time(),
        }
    );

    $self->userLogger->notice(
        "Device authorization approved by user $user for client "
          . $device_auth->{client_id} );

    $self->auditLog(
        $req,
        code      => "ISSUER_OIDC_DEVICE_AUTH_APPROVED",
        rp        => $device_auth->{rp},
        user_code => $device_auth->{user_code},
        user      => $user,
        message   =>
          "Device authorization approved by $user for RP $device_auth->{rp}",
    );

    return $self->p->sendHtml(
        $req, 'device',
        params => {
            DEVICE_APPROVED => 1,
            CLIENT_ID       => $device_auth->{client_id},
            SCOPE           => $device_auth->{scope},
            MSG             => 'deviceApproved',
        }
    );
}

# PRIVATE METHODS

sub _generateDeviceCode {
    my ($self) = @_;

    # 32 bytes of random data, hex encoded
    return unpack( 'H*', Crypt::URandom::urandom(32) );
}

sub _generateUserCode {
    my ($self) = @_;
    my $length =
      $self->conf->{oidcServiceDeviceAuthorizationUserCodeLength} || 8;
    my $chars     = USER_CODE_CHARS;
    my $chars_len = length($chars);
    my $code      = '';

    # Use rejection sampling to avoid modulo bias
    # For chars_len=20, largest multiple fitting in a byte is 240 (12*20)
    my $max_valid = int( 256 / $chars_len ) * $chars_len;

    while ( length($code) < $length ) {

        # Get a batch of random bytes (request extra to reduce iterations)
        my $bytes = Crypt::URandom::urandom( ( $length - length($code) ) * 2 );
        foreach my $b ( split //, $bytes ) {
            my $val = ord($b);

            # Reject values that would cause modulo bias
            next if $val >= $max_valid;

            $code .= substr( $chars, $val % $chars_len, 1 );
            last if length($code) >= $length;
        }
    }
    return $code;
}

sub _formatUserCode {
    my ( $self, $code ) = @_;

    # Format as XXXX-XXXX for readability
    if ( length($code) == 8 ) {
        return substr( $code, 0, 4 ) . '-' . substr( $code, 4, 4 );
    }
    return $code;
}

sub _findByUserCode {
    my ( $self, $user_code ) = @_;

    # Look up the user_code session to get the device_code_hash
    my $user_code_hash = sha256_hex($user_code);

    my $user_code_session =
      $self->p->getApacheSession( $user_code_hash, kind => sessionKind, );

    unless ( $user_code_session && $user_code_session->data ) {
        $self->logger->debug("User code session not found: $user_code");
        return undef;
    }

    # Check expiration
    if ( time() > ( $user_code_session->data->{expires_at} || 0 ) ) {
        $self->logger->debug("User code expired: $user_code");
        $user_code_session->remove;
        return undef;
    }

    my $device_code_hash = $user_code_session->data->{device_code_hash};
    return $self->_getDeviceAuthByHash($device_code_hash);
}

sub _findByDeviceCode {
    my ( $self, $device_code ) = @_;

    my $device_code_hash = sha256_hex($device_code);
    return $self->_getDeviceAuthByHash($device_code_hash);
}

sub _getDeviceAuthByHash {
    my ( $self, $device_code_hash ) = @_;

    my $session =
      $self->p->getApacheSession( $device_code_hash, kind => sessionKind, );

    unless ( $session && $session->data ) {
        $self->logger->debug("Device auth session not found");
        return undef;
    }

    # Check expiration
    if ( time() > ( $session->data->{expires_at} || 0 ) ) {
        $self->logger->debug("Device auth session expired");
        $session->remove;
        return undef;
    }

    # Return session data with session reference for updates
    my $data = { %{ $session->data } };
    $data->{_session}          = $session;
    $data->{_device_code_hash} = $device_code_hash;

    return $data;
}

sub _updateDeviceAuthStatus {
    my ( $self, $device_auth, $status, $extra ) = @_;

    my $session = $device_auth->{_session};
    return unless $session;

    # Update status
    my $info = { status => $status };

    # Add extra fields
    if ($extra) {
        for my $key ( keys %$extra ) {
            $info->{$key} = $extra->{$key};
        }
    }

    # Update session
    $self->p->getApacheSession(
        $session->id,
        kind => sessionKind,
        info => $info,
    );
}

sub _deleteDeviceAuth {
    my ( $self, $device_auth ) = @_;

    # Delete the device_code session
    if ( my $session = $device_auth->{_session} ) {
        $session->remove;
    }

    # Also delete the user_code lookup session
    if ( my $user_code = $device_auth->{user_code} ) {
        my $user_code_hash = sha256_hex($user_code);
        my $user_code_session =
          $self->p->getApacheSession( $user_code_hash, kind => sessionKind, );
        $user_code_session->remove if $user_code_session;
    }
}

sub _generateTokens {
    my ( $self, $req, $device_auth, $rp ) = @_;

    # Validate PKCE if it was used
    my $code_challenge        = $device_auth->{code_challenge};
    my $code_challenge_method = $device_auth->{code_challenge_method};

    if ($code_challenge) {
        my $code_verifier = $req->param('code_verifier');

        # Verify code_verifier is provided when code_challenge exists
        unless ($code_verifier) {
            $self->logger->error(
                "code_verifier is required when code_challenge was provided");
            return $self->_sendTokenError( $req, 'invalid_grant',
                'code_verifier is required' );
        }

        # Use the OIDC issuer's validatePKCEChallenge method
        unless (
            $self->oidc->validatePKCEChallenge(
                $code_verifier, $code_challenge, $code_challenge_method
            )
          )
        {
            $self->logger->error(
                "PKCE validation failed for device code grant");
            return $self->_sendTokenError( $req, 'invalid_grant',
                'PKCE validation failed' );
        }
        $self->logger->debug("PKCE validation successful");
    }

    my $scope = $device_auth->{scope};
    my $user  = $device_auth->{user};

    # Verify user session is still valid
    my $user_session_id = $device_auth->{user_session_id};
    my $session         = $self->p->getApacheSession($user_session_id);

    unless ($session) {
        $self->logger->error("User session not found for device authorization");
        $self->_deleteDeviceAuth($device_auth);
        return $self->_sendTokenError( $req, 'access_denied',
            'User session no longer valid' );
    }

    my $session_data = $session->data;
    my $timeout      = $self->conf->{timeout};
    my $utime        = $session_data->{_utime} || 0;

    if ( time() > $utime + $timeout ) {
        $self->logger->error("User session expired for device authorization");
        $self->_deleteDeviceAuth($device_auth);
        return $self->_sendTokenError( $req, 'access_denied',
            'User session expired' );
    }

    # Hook: allows plugins to modify session data before token creation
    # (e.g. replace with synthetic session for organizational devices).
    # The hook may also update $device_auth->{user_session_id} to point
    # to a different (e.g. synthetic) session.
    my $h = $self->p->processHook( $req, 'oidcDeviceCodeGrant',
        $device_auth, $rp, $session_data );
    if ( $h != PE_OK ) {
        $self->_deleteDeviceAuth($device_auth);
        return $self->_sendTokenError( $req, 'access_denied' );
    }

    # Re-read values in case the hook changed them
    $user_session_id = $device_auth->{user_session_id};
    $scope           = $device_auth->{scope};

    # Generate access token
    my $access_token_extra = {
        scope      => $scope,
        rp         => $rp,
        grant_type => "device_code",
    };
    $access_token_extra->{user_session_id} = $user_session_id
      if $user_session_id;

    my $access_token =
      $self->oidc->newAccessToken( $req, $rp, $scope, $session_data,
        $access_token_extra );

    unless ($access_token) {
        $self->logger->error("Failed to create access token");
        return $self->_sendTokenError( $req, 'server_error' );
    }

    my $expires_in =
      $self->oidc->rpOptions->{$rp}
      ->{oidcRPMetaDataOptionsAccessTokenExpiration}
      || $self->conf->{oidcServiceAccessTokenExpiration}
      || 3600;

    my $response = {
        access_token => "$access_token",
        token_type   => 'Bearer',
        expires_in   => $expires_in + 0,
        scope        => $scope,
    };

    # Generate ID token if openid scope is requested
    if ( $scope =~ /\bopenid\b/ ) {
        my $id_token =
          $self->oidc->_generateIDToken( $req, $rp, $scope, $session_data, 0 );
        if ($id_token) {
            $response->{id_token} = $id_token;
        }
    }

    # Generate refresh token if allowed
    if ( $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsRefreshToken} ) {
        my $refresh_token_data = {
            scope        => $scope,
            client_id    => $device_auth->{client_id},
            _session_uid => $session_data->{_user},
            auth_time    => $session_data->{_lastAuthnUTime},
            grant_type   => "device_code",
            %$session_data,
        };

        # Offline refresh token if offline_access scope was requested
        # and allowed by RP configuration
        my $is_offline = 0;
        if (    $self->oidc->_hasScope( 'offline_access', $scope )
            and
            $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsAllowOffline} )
        {
            $is_offline = 1;
        }

        $refresh_token_data->{user_session_id} = $user_session_id
          unless $is_offline;

        my $refresh_token =
          $self->oidc->newRefreshToken( $rp, $refresh_token_data, $is_offline );

        if ($refresh_token) {
            $response->{refresh_token} = $refresh_token->id;
        }
    }

    # Clean up the device authorization
    $self->_deleteDeviceAuth($device_auth);

    $self->logger->debug("Device code grant completed for RP $rp");

    $self->auditLog(
        $req,
        code      => "ISSUER_OIDC_DEVICE_AUTH_TOKEN_GRANTED",
        rp        => $rp,
        user_code => $device_auth->{user_code},
        user      => $user,
        message   => "Device code exchanged for tokens by $user for RP $rp",
    );

    $req->response( $self->p->sendJSONresponse( $req, $response ) );
    return PE_SENDRESPONSE;
}

sub _sendDeviceError {
    my ( $self, $req, $error, $description ) = @_;

    my $response = { error => $error };
    $response->{error_description} = $description if $description;

    # Return PSGI response directly (used by deviceAuthorizationEndpoint route)
    return $self->p->sendJSONresponse( $req, $response, code => 400 );
}

sub _sendTokenError {
    my ( $self, $req, $error, $description ) = @_;

    my $response = { error => $error };
    $response->{error_description} = $description if $description;

    # authorization_pending and slow_down should return 400
    # expired_token and access_denied should return 400
    $req->response(
        $self->p->sendJSONresponse( $req, $response, code => 400 ) );
    return PE_SENDRESPONSE;
}

sub _showVerificationError {
    my ( $self, $req, $msg ) = @_;

    return $self->p->sendHtml(
        $req, 'device',
        params => {
            USER_CODE => $req->param('user_code') || '',
            MSG       => $msg,
            ERROR     => 1,
        }
    );
}

# CrowdSec integration methods

sub _reportInvalidUserCode {
    my ( $self, $req, $user_code ) = @_;

    my $crowdsec = $self->crowdsec;
    return unless $crowdsec && $crowdsec->can('alert');

    my $ip  = $req->address;
    my $msg = "RFC 8628: Invalid user_code attempt from $ip (code: $user_code)";

    $crowdsec->alert(
        $ip, $msg,
        {
            scenario => 'llng/device-auth-bruteforce',
            reason   => $msg,
        }
    );
    $self->logger->debug("Reported invalid user_code attempt to CrowdSec");
}

1;
