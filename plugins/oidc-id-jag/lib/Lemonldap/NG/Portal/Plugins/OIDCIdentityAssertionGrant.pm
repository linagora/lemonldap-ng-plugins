# Identity Assertion JWT Authorization Grant (ID-JAG), also known as
# Cross-App Access (XAA).
#
# See draft-ietf-oauth-identity-assertion-authz-grant
#
# This plugin implements the *Identity Provider Authorization Server* role: it
# answers RFC 8693 token exchange requests asking for a
# "urn:ietf:params:oauth:token-type:id-jag" token, and returns a signed JWT
# that the requesting client can then present to another Authorization Server
# (the "Resource Authorization Server") using the JWT Bearer grant.
package Lemonldap::NG::Portal::Plugins::OIDCIdentityAssertionGrant;

use strict;
use Mouse;
use JSON;
use Crypt::JWT qw(decode_jwt);
use Digest::SHA qw(sha256_hex);
use Lemonldap::NG::Common::Apache::Session;
use Lemonldap::NG::Common::JWT qw(getJWTHeader);
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_SENDRESPONSE
);

our $VERSION = '0.1.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

use constant ID_JAG_TOKEN_TYPE => 'urn:ietf:params:oauth:token-type:id-jag';
use constant ID_JAG_TYP        => 'oauth-id-jag+jwt';
use constant TOKEN_EXCHANGE_GRANT =>
  'urn:ietf:params:oauth:grant-type:token-exchange';

# Session key used by the oidc-rar plugin to carry RFC 9396 granted
# authorization_details across the code / refresh / access token sessions.
# Read-only coupling: no code dependency, and everything below degrades to
# "no authorization_details" when oidc-rar is not installed.
use constant RAR_SESSION_KEY => '_rar_details';

# Prefix of the fixed-id sessions indexing `sid` -> user session id. See
# indexIdTokenSid().
use constant SID_INDEX_PREFIX => 'idjag-sid:';

# INTERFACE
use constant hook => {
    oidcGotTokenExchange => 'handleIdentityAssertionGrant',
    oidcGenerateMetadata => 'advertiseIdentityChaining',
    oidcGenerateIDToken  => 'indexIdTokenSid',
};

# Entry point: called for every RFC 8693 token exchange request.
#
# Only PE_OK (let other token exchange plugins try) and PE_SENDRESPONSE are
# meaningful here.
sub handleIdentityAssertionGrant {
    my ( $self, $req, $rp ) = @_;

    my $requestedTokenType = $req->param('requested_token_type') || '';
    unless ( $requestedTokenType eq ID_JAG_TOKEN_TYPE ) {
        return PE_OK;
    }

    $self->logger->debug("ID-JAG requested by RP $rp");
    $req->response( $self->_run( $req, $rp ) );
    return PE_SENDRESPONSE;
}

# Advertise the grant in /.well-known/openid-configuration.
#
# Core LemonLDAP::NG does not know about ID-JAG, so the token exchange grant
# and the identity chaining token types are added here.
sub advertiseIdentityChaining {
    my ( $self, $req, $metadata ) = @_;

    my $rpOptions = $self->conf->{oidcRPMetaDataOptions} || {};
    return PE_OK
      unless grep { $_->{oidcRPMetaDataOptionsAllowIdJagGrant} }
      values %$rpOptions;

    my $grants = $metadata->{grant_types_supported} ||= [];
    push @$grants, TOKEN_EXCHANGE_GRANT
      unless grep { $_ eq TOKEN_EXCHANGE_GRANT } @$grants;

    $metadata->{identity_chaining_requested_token_types_supported} =
      [ID_JAG_TOKEN_TYPE];

    return PE_OK;
}

sub _run {
    my ( $self, $req, $rp ) = @_;
    my $oidc = $self->oidc;

    # 1. The requesting client must be explicitly allowed and confidential
    unless ( $oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsAllowIdJagGrant} ) {
        $self->userLogger->error(
            "Identity Assertion grant is not allowed for RP $rp");
        return $oidc->sendOIDCError( $req, 'unauthorized_client', 400 );
    }
    if ( $oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsPublic} ) {
        $self->logger->error(
            "Identity Assertion grant cannot be used by public clients");
        return $oidc->sendOIDCError( $req, 'unauthorized_client', 400 );
    }

    # 2. Resolve the requested audience into a known Resource Server
    my $audience = $req->param('audience');
    unless ($audience) {
        $self->logger->error('ID-JAG request without audience');
        return $oidc->sendOIDCError( $req, 'invalid_request', 400,
            'audience is required' );
    }
    my $target = $self->_findTargetRp($audience);
    unless ($target) {
        $self->userLogger->error(
            "No relying party declares $audience as ID-JAG audience");
        return $oidc->sendOIDCError( $req, 'invalid_target', 400 );
    }

    # 3. Is $rp allowed to get a token for $target?
    my $list =
      $oidc->rpOptions->{$target}->{oidcRPMetaDataOptionsTokenXAuthorizedRP};
    unless ( $list and grep { $_ eq $rp } split( /[,;\s]+/, $list ) ) {
        $self->userLogger->error(
            "RP $rp is not authorized to request an ID-JAG for $target");
        return $oidc->sendOIDCError( $req, 'access_denied', 400 );
    }

    # 4. Resolve the subject from the presented token. $tokenData is the
    #    subject token's own session data, kept for the claims that travel
    #    with the grant rather than with the user (authorization_details).
    my ( $userData, $tokenData ) = $self->_getUserData( $req, $rp );
    return $oidc->sendOIDCError( $req, 'invalid_grant', 400 )
      unless $userData;

    my $sub = $oidc->getUserIDForRP( $req, $target, $userData );
    unless ( defined $sub and $sub ne '' ) {
        $self->logger->error(
            "Unable to compute subject identifier for RP $target");
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }

    # 5. Let the target RP access rule have the last word
    $req->userData($userData);
    if ( my $rule = $oidc->rpRules->{$target} ) {
        my $ruleVariables = { %$userData, _oidc_grant_type => 'idjag' };
        unless ( $rule->( $req, $ruleVariables ) ) {
            $self->userLogger->warn( "User did not validate the access rule "
                  . "of relying party $target during ID-JAG grant" );
            return $oidc->sendOIDCError( $req, 'access_denied', 400 );
        }
    }

    # 6. Narrow down requested scopes: the client cannot obtain more than the
    #    subject token itself was granted, and the target RP policy applies on
    #    top of that.
    my $scope = $self->_assertedScope( $req, $target, $tokenData );

    # 7. Build and sign the assertion
    my $expiration =
         $oidc->rpOptions->{$target}->{oidcRPMetaDataOptionsIdJagExpiration}
      || $self->conf->{oidcServiceIdJagExpiration}
      || 300;

    # Every value below is forced into scalar context and stringified before it
    # reaches this hash. `$req->param` is list-context aware: interpolating it
    # straight into a hash literal lets a client repeat the parameter and
    # inject -- or overwrite -- arbitrary claims, `sub` included.
    #
    # The draft defines `resource` as a single value. Rather than silently
    # keeping one of several, refuse the ambiguity outright.
    my @resources = $req->param('resource');
    if ( @resources > 1 ) {
        $self->userLogger->error(
            'ID-JAG request with several resource parameters');
        return $oidc->sendOIDCError( $req, 'invalid_request', 400,
            'resource must be a single value' );
    }
    my $resource = $resources[0];

    my $payload = {
        iss       => $oidc->get_issuer($req),
        sub       => "$sub",
        aud       => "$audience",
        client_id => $self->_clientIdForTarget( $rp, $target ),
        jti       => $oidc->generateNonce,
        iat       => time,
        exp       => time + $expiration,
    };
    $payload->{scope}    = "$scope"    if length $scope;
    $payload->{resource} = "$resource" if defined $resource and length $resource;

    # RFC 9396 authorization_details granted to the subject token travel with
    # the assertion, narrowed down by the target RP type allowlist.
    if ( my $details = $self->_forwardedAuthorizationDetails( $tokenData,
            $target ) )
    {
        $payload->{authorization_details} = $details;
    }

    my $h =
      $self->p->processHook( $req, 'oidcGenerateIdJag', $payload, $rp, $target,
        $userData );
    return $oidc->sendOIDCError( $req, 'server_error', 500 ) if ( $h != PE_OK );

    my $alg = $self->_signatureAlg($target);
    unless ($alg) {
        return $oidc->sendOIDCError( $req, 'server_error', 500 );
    }

    # createJWT() drops the `typ` header when the partner RP has NoJwtHeader,
    # which would produce an assertion no Resource Authorization Server can
    # recognise. Fail loudly instead of shipping a broken one.
    if ( $oidc->rpOptions->{$target}->{oidcRPMetaDataOptionsNoJwtHeader} ) {
        $self->logger->error( "Relying party $target has NoJwtHeader set: an "
              . 'ID-JAG cannot carry its ' . ID_JAG_TYP . ' type header' );
        return $oidc->sendOIDCError( $req, 'server_error', 500 );
    }

    my $assertion =
      $oidc->createJWT( $payload, $alg, $target, { typ => ID_JAG_TYP } );
    unless ($assertion) {
        $self->logger->error('Unable to build ID-JAG');
        return $oidc->sendOIDCError( $req, 'server_error', 500 );
    }

    $self->auditLog(
        $req,
        code    => 'ISSUER_OIDC_ID_JAG',
        rp      => $rp,
        message => "RP $rp got an ID-JAG for $audience (user $sub)",
        user    => $userData->{ $self->conf->{whatToTrace} },
    );

    return $self->p->sendJSONresponse(
        $req,
        {
            access_token      => "$assertion",
            issued_token_type => ID_JAG_TOKEN_TYPE,
            token_type        => 'N_A',
            expires_in        => $expiration + 0,
            ( $scope ? ( scope => "$scope" ) : () ),
        }
    );
}

# The scope carried by the assertion.
#
# Two bounds, both mandatory: what the subject token itself was granted, and
# the policy of the target relying party. Without the first one a client
# holding a token scoped `openid profile` could ask for -- and get -- an
# assertion carrying `admin`, since getScope() echoes undeclared scopes unless
# oidcServiceAllowOnlyDeclaredScopes is set.
sub _assertedScope {
    my ( $self, $req, $target, $tokenData ) = @_;

    my $requested = scalar $req->param('scope');
    $requested = '' unless defined $requested;

    my $granted = $tokenData->{scope};
    if ( defined $granted and $granted =~ /\S/ ) {
        my %ok = map { $_ => 1 } grep { length } split /\s+/, $granted;
        $requested = join ' ',
          grep { $ok{$_} } grep { length } split /\s+/,
          ( $requested =~ /\S/ ? $requested : $granted );
    }

    my $scope = $self->oidc->getScope( $req, $target, $requested );
    return defined $scope ? $scope : '';
}

# Find the RP declaring $audience as its Authorization Server identifier.
#
# The match must be unique: every later decision -- the TokenXAuthorizedRP
# allowlist, the access rule, the scope policy, the subject computation, the
# signing algorithm -- is taken from the RP found here, while the remote server
# only ever sees the audience string. Two RPs sharing an audience would let the
# laxer one silently govern assertions meant for the other.
sub _findTargetRp {
    my ( $self, $audience ) = @_;
    my $rpOptions = $self->oidc->rpOptions;

    my @targets = grep {
        ( $rpOptions->{$_}->{oidcRPMetaDataOptionsIdJagAudience} || '' ) eq
          $audience
    } sort keys %$rpOptions;

    if ( @targets > 1 ) {
        $self->logger->error( "Relying parties "
              . join( ', ', @targets )
              . " all declare $audience as ID-JAG audience; refusing to guess"
        );
        return;
    }

    return $targets[0];
}

# client_id claim: identifier of the requesting client *at the Resource
# Authorization Server*. It defaults to its LLNG client_id.
sub _clientIdForTarget {
    my ( $self, $rp, $target ) = @_;

    return $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsIdJagClientId}
      || $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};
}

# The Resource Authorization Server validates the ID-JAG against the published
# JWKS of this OP: symmetric and unsigned assertions are refused.
sub _signatureAlg {
    my ( $self, $target ) = @_;

    my $alg =
      $self->oidc->rpOptions->{$target}->{oidcRPMetaDataOptionsIdJagSignAlg};
    unless ($alg) {
        $alg =
          ( ( $self->conf->{oidcServiceKeyTypeSig} || 'RSA' ) eq 'EC' )
          ? 'ES256'
          : 'RS256';
    }
    if ( $alg eq 'none' or $alg =~ /^HS/ ) {
        $self->logger->error(
            "ID-JAG must be signed with an asymmetric algorithm, got $alg");
        return;
    }
    return $alg;
}

# Resolve the subject_token into ( user session data, token session data ).
#
# The draft allows an Identity Assertion (ID Token) or a Refresh Token as
# subject_token. LemonLDAP::NG additionally accepts an Access Token, which is
# resolved the same way.
sub _getUserData {
    my ( $self, $req, $rp ) = @_;
    my $oidc = $self->oidc;

    my $subjectToken = $req->param('subject_token');
    unless ($subjectToken) {
        $self->userLogger->error('ID-JAG request without subject_token');
        return;
    }

    my $type = $req->param('subject_token_type') || '';
    $type =~ s/^urn:ietf:params:oauth:token-type://;

    my $tokenData;
    if ( $type eq 'id_token' ) {
        $tokenData = $self->_getDataFromIdToken( $req, $rp, $subjectToken );
    }
    elsif ( $type eq 'refresh_token' ) {
        my $s = $oidc->getRefreshToken($subjectToken);
        $tokenData = $s->data if $s;
    }
    elsif ( $type eq 'access_token' or $type eq '' ) {
        my $s = $oidc->getAccessToken($subjectToken);
        $tokenData = $s->data if $s;
    }
    else {
        $self->userLogger->error(
            "Unsupported subject_token_type for ID-JAG: $type");
        return;
    }

    unless ($tokenData) {
        $self->userLogger->error('Unable to validate ID-JAG subject_token');
        return;
    }

    # The subject_token MUST have been issued to the authenticated client
    my $clientId = $oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};
    my $tokenClientId = $tokenData->{client_id} || '';
    my $tokenRp       = $tokenData->{rp}        || '';
    unless ( $tokenClientId eq $clientId or $tokenRp eq $rp ) {
        $self->userLogger->error(
            "ID-JAG subject_token was not issued to client $clientId");
        return;
    }

    # Online tokens are tied to a SSO session, offline ones embed a copy of
    # the user attributes
    my $sessionId = $tokenData->{user_session_id};
    unless ($sessionId) {
        return ( $tokenData, $tokenData )
          if $tokenData->{ $self->conf->{whatToTrace} };
        $self->userLogger->error(
            'ID-JAG subject_token is not tied to a user session');
        return;
    }

    my $userData = $self->p->HANDLER->retrieveSession( $req, $sessionId );
    unless ($userData) {
        $self->logger->error(
            'Unable to find the user session tied to ID-JAG subject_token');
        return;
    }

    return ( $userData, $tokenData );
}

# RFC 9396 authorization_details carried by the subject token, narrowed down
# by the type allowlist of the target relying party.
#
# The details were granted by *this* OP to the requesting client; the target
# authorization server is a different trust domain, so an entry whose type is
# not part of what the target accepts is dropped rather than forwarded. An
# empty allowlist means "no restriction at that level", exactly like in
# oidc-rar. Plugins can still amend the list through the oidcGenerateIdJag
# hook.
sub _forwardedAuthorizationDetails {
    my ( $self, $tokenData, $target ) = @_;

    my $details = $tokenData->{ &RAR_SESSION_KEY };
    return unless $details and ref($details) eq 'ARRAY' and @$details;

    # Fail closed: the target authorization server is a different trust
    # domain, so it has to declare which types it accepts. No allowlist means
    # nothing travels, not "everything travels".
    my $allowed = $self->oidc->rpOptions->{$target}
      ->{oidcRPMetaDataOptionsAuthorizationDetailsTypes};
    unless ( defined $allowed and $allowed =~ /\S/ ) {
        $self->logger->debug( "ID-JAG: $target declares no accepted "
              . 'authorization_details type, forwarding none' );
        return;
    }

    # Same splitting rule as oidc-rar, so one configuration string means the
    # same thing on both paths.
    my %ok = map { $_ => 1 } grep { length } split /\s*,\s*/, $allowed;
    my @kept = grep { $ok{ $_->{type} // '' } } @$details;

    unless (@kept) {
        $self->logger->debug(
            "ID-JAG: no authorization_details type accepted by $target");
        return;
    }
    if ( @kept < @$details ) {
        $self->logger->debug( 'ID-JAG: dropped '
              . ( @$details - @kept )
              . " authorization_details entry(ies) not accepted by $target" );
    }
    return \@kept;
}

# Hook: oidcGenerateIDToken
#
# The `sid` claim of an ID Token is only persisted by LemonLDAP::NG on refresh
# token sessions, so resolving an ID Token back to its user session used to
# require the client to be allowed to get refresh tokens. Maintain our own
# reverse index instead: one short lived, fixed-id session per issued ID
# Token, living exactly as long as the ID Token it describes.
#
# Only relying parties allowed to request an ID-JAG pay for this.
sub indexIdTokenSid {
    my ( $self, $req, $payload, $rp, $sessionData ) = @_;

    return PE_OK
      unless $self->oidc->rpOptions->{$rp}
      ->{oidcRPMetaDataOptionsAllowIdJagGrant};

    my $sid = $payload->{sid} or return PE_OK;

    # In the offline refresh flow core hands us the *refresh token* session,
    # not the SSO session, so `_session_id` would be a token session id. That
    # would overwrite the good entry with one retrieveSession() -- which forces
    # kind SSO -- can never resolve.
    my $kind = $sessionData->{_session_kind} || '';
    unless ( $kind eq 'SSO' ) {
        $self->logger->debug(
            "ID-JAG: not indexing sid $sid, session kind is '$kind'");
        return PE_OK;
    }
    my $id = $sessionData->{_session_id} or return PE_OK;

    my $ttl =
         $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsIDTokenExpiration}
      || $self->conf->{oidcServiceIDTokenExpiration}
      || 3600;

    my $session = $self->p->getApacheSession(
        $self->_sidIndexId( $rp, $sid ),
        kind => $self->oidc->sessionKind,
        info => {
            _type           => 'idjag_sid',
            _utime          => time() - $self->conf->{timeout} + $ttl,
            user_session_id => $id,
            rp              => $rp,
        },
        force     => 1,
        hashStore => 0,
    );
    $self->logger->debug("Unable to index ID Token sid $sid") unless $session;

    return PE_OK;
}

# The index key is scoped to the relying party. `sid` alone is not a safe key:
# once the user authenticated against an upstream OP, getSidFromSession()
# returns that OP's `_oidc_sid` verbatim, which is the SAME value for every
# relying party and is chosen by a third party. An unscoped key would let one
# RP resolve a `sid` it learned elsewhere into another RP's user session.
sub _sidIndexId {
    my ( $self, $rp, $sid ) = @_;
    return sha256_hex( SID_INDEX_PREFIX . $rp . '|' . $sid );
}

# Resolve an ID Token issued by this OP into token session data.
#
# Two lookups, in order:
#   1. our own `sid` index (see indexIdTokenSid), which works for every client
#      but only knows about ID Tokens issued while this plugin was loaded;
#   2. the historical search of OIDC sessions on `_oidc_sid`, which finds the
#      refresh token session carrying the same sid. It also covers sessions
#      opened against an upstream OP, where `_oidc_sid` is the OP's own sid.
#
# Route 1 returns the user session id only, so no authorization_details come
# with it; route 2 returns the full refresh token session data.
sub _getDataFromIdToken {
    my ( $self, $req, $rp, $idToken ) = @_;
    my $oidc = $self->oidc;

    $idToken = $oidc->decryptJwt($idToken) or return;

    my $payload = $self->_verifySelfIssuedJwt( $rp, $idToken );
    unless ($payload) {
        $self->userLogger->error('Unable to verify ID-JAG subject ID Token');
        return;
    }

    my $clientId = $oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};
    unless ( ( $payload->{azp} || '' ) eq $clientId ) {
        $self->userLogger->error("ID Token was not issued to client $clientId");
        return;
    }

    # Crypt::JWT skips every registered-claim check when decode_payload is 0,
    # which _verifySelfIssuedJwt has to use (see #2748), so validate here.
    unless ( $self->_checkIdTokenClaims( $req, $rp, $payload, $clientId ) ) {
        return;
    }

    my $sid = $payload->{sid};
    unless ($sid) {
        $self->userLogger->error('ID Token has no sid claim');
        return;
    }

    # 1. Our own reverse index, scoped to this relying party
    my $index = $self->p->getApacheSession(
        $self->_sidIndexId( $rp, $sid ),
        kind      => $oidc->sessionKind,
        hashStore => 0,
    );
    if (    $index
        and ( $index->data->{rp} || '' ) eq $rp
        and $index->data->{user_session_id} )
    {
        # Confirm the resolved session really is the one this `sid` names,
        # rather than trusting the index blindly.
        my $userData =
          $self->p->HANDLER->retrieveSession( $req,
            $index->data->{user_session_id} );
        if ( $userData
            and $oidc->getSidFromSession( $rp, $userData ) eq $sid )
        {
            return {
                rp              => $rp,
                client_id       => $clientId,
                user_session_id => $index->data->{user_session_id},
            };
        }
        $self->logger->debug(
            'ID-JAG: stale sid index entry, falling back to session search');
    }

    # 2. Refresh token session carrying the same sid
    # _storeOpts returns the live configuration hashref, not a copy: mutating
    # it would permanently add `backend` to the global storage options handed
    # to every later session. Copy first, like core does.
    my %opts = $oidc->_storeOpts;
    my %store = %{ $opts{storageModuleOptions} || {} };
    $store{backend} = $opts{storageModule};

    my $sessions = Lemonldap::NG::Common::Apache::Session->searchOn( \%store,
        '_oidc_sid', $sid );

    for my $id (
        grep {
            ( $sessions->{$_}->{_session_kind} || '' ) eq $oidc->sessionKind
        }
        keys %{ $sessions || {} }
      )
    {
        my $session =
          $oidc->getOpenIDConnectSession( $id, 'refresh_token',
            hashStore => 0 );
        return $session->data if $session;
    }

    $self->userLogger->error("No session found for ID Token sid $sid");
    return;
}

# Validate the registered claims of a subject ID Token.
#
# `decode_jwt(..., decode_payload => 0)` returns the payload as a raw string,
# which disables all of Crypt::JWT's own verify_exp / verify_nbf / verify_iss /
# verify_aud handling. Without this an ID Token that expired months ago is
# still accepted as a subject_token, and route 2 resolves it through a refresh
# token session that outlives it by far.
sub _checkIdTokenClaims {
    my ( $self, $req, $rp, $payload, $clientId ) = @_;

    my $skew = $self->conf->{oidcServiceIdJagAllowedSkew} // 30;
    my $now  = time;

    unless ( $payload->{exp} and $payload->{exp} + $skew > $now ) {
        $self->userLogger->error('ID-JAG subject ID Token is expired');
        return 0;
    }
    if ( $payload->{nbf} and $payload->{nbf} - $skew > $now ) {
        $self->userLogger->error('ID-JAG subject ID Token is not valid yet');
        return 0;
    }

    my $issuer = $self->oidc->get_issuer($req);
    unless ( ( $payload->{iss} || '' ) eq $issuer ) {
        $self->userLogger->error(
            'ID-JAG subject ID Token was not issued by ' . $issuer );
        return 0;
    }

    my @aud =
      ref $payload->{aud} eq 'ARRAY'
      ? @{ $payload->{aud} }
      : ( $payload->{aud} // () );
    unless ( grep { $_ eq $clientId } @aud ) {
        $self->userLogger->error(
            "ID-JAG subject ID Token is not addressed to $clientId");
        return 0;
    }

    return 1;
}

# Verify a JWT signed by this OP for $rp. The algorithm is pinned to the RP
# configuration to avoid algorithm substitution.
sub _verifySelfIssuedJwt {
    my ( $self, $rp, $jwt ) = @_;
    my $oidc = $self->oidc;

    my $alg = $oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsIDTokenSignAlg};
    if ( !$alg or $alg eq 'none' ) {
        $self->logger->error(
            "Unsigned ID Tokens cannot be used as ID-JAG subject_token");
        return;
    }

    # An HS* ID Token is verified with the client's own client_secret, so the
    # client can mint one with any claims it likes -- it is evidence of
    # nothing. _signatureAlg() already refuses symmetric algorithms for the
    # assertions we issue; apply the same rule to the tokens we consume.
    if ( $alg =~ /^HS/ ) {
        $self->logger->error(
                "ID Tokens signed with $alg cannot be used as ID-JAG "
              . 'subject_token: the client holds the signing key. Configure an '
              . 'asymmetric oidcRPMetaDataOptionsIDTokenSignAlg, or send the '
              . 'refresh or access token instead' );
        return;
    }
    my $header = getJWTHeader($jwt);
    unless ( ( $header->{alg} || '' ) eq $alg ) {
        $self->logger->error( "ID Token is signed with "
              . ( $header->{alg} || 'nothing' )
              . " instead of $alg" );
        return;
    }

    my @keys;
    if ( $alg =~ /^HS/ ) {
        my $secret =
          $oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientSecret};
        return unless $secret;
        @keys = ($secret);
    }
    else {
        my $list = $oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsSigningKey}
          || $self->conf->{oidcServiceSignatureKey};
        for my $keyId ( split( /\s*,\s*/, $list || '' ) ) {
            my $key = $oidc->get_public_key($keyId) or next;
            push @keys, \$key->{public};
        }
    }

    for my $key (@keys) {

        # JSON decoding is done here due to #2748
        my $payload = eval {
            from_json(
                decode_jwt(
                    token          => $jwt,
                    key            => $key,
                    accepted_alg   => $alg,
                    decode_payload => 0,
                )
            );
        };
        return $payload unless $@;
        $self->logger->debug("Unable to verify ID Token: $@");
    }

    return;
}

1;
__END__

=pod

=encoding utf8

=head1 NAME

Lemonldap::NG::Portal::Plugins::OIDCIdentityAssertionGrant - Identity
Assertion JWT Authorization Grant (ID-JAG / Cross-App Access)

=head1 DESCRIPTION

This plugin implements the Identity Provider Authorization Server role of
L<draft-ietf-oauth-identity-assertion-authz-grant|https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/>,
also known as Cross-App Access (XAA).

A client authenticated on the token endpoint may exchange one of its tokens for
an B<ID-JAG>: a short lived JWT (C<typ: oauth-id-jag+jwt>) that it can present
to another Authorization Server using the JWT Bearer grant, in order to get an
access token for that server's APIs.

  POST /oauth2/token
  Authorization: Basic ...


  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
  &requested_token_type=urn:ietf:params:oauth:token-type:id-jag
  &audience=https://resource.example.com
  &subject_token=<ID, refresh or access token>
  &subject_token_type=urn:ietf:params:oauth:token-type:refresh_token
  &scope=...

The C</.well-known/openid-configuration> document is enriched through the
C<oidcGenerateMetadata> hook: C<grant_types_supported> gains
C<urn:ietf:params:oauth:grant-type:token-exchange> and
C<identity_chaining_requested_token_types_supported> is published.

=head1 CONFIGURATION

On the B<requesting client>:

=over

=item C<oidcRPMetaDataOptionsAllowIdJagGrant>: enables the grant (also loads
this plugin).

=item C<oidcRPMetaDataOptionsIdJagClientId>: value of the C<client_id> claim,
when the client is not registered under the same identifier on the Resource
Authorization Server.

=back

On the B<resource> relying party:

=over

=item C<oidcRPMetaDataOptionsIdJagAudience>: issuer identifier of its
Authorization Server. This is the value clients must send as C<audience>.

=item C<oidcRPMetaDataOptionsTokenXAuthorizedRP>: list of relying parties
allowed to request an ID-JAG for it.

=item C<oidcRPMetaDataOptionsIdJagSignAlg>: signature algorithm (asymmetric
only, defaults to RS256 or ES256).

=item C<oidcRPMetaDataOptionsIdJagExpiration>: assertion lifetime, defaults to
C<oidcServiceIdJagExpiration> (300s).

=item C<oidcRPMetaDataOptionsAuthorizationDetailsTypes> (from the C<oidc-rar>
plugin): when set, restricts which RFC 9396 C<authorization_details> types are
copied from the subject token into the assertion.

=back

=head1 LIMITATIONS

The draft is not stabilized yet: claim names and behaviour may still change.

=over

=item The C<client_id> claim can only be overridden globally per client, not
per (client, resource) pair.

=item C<authorization_details> forwarded from an ID Token C<subject_token>
requires that ID Token to resolve through a refresh token session; the C<sid>
index alone carries the user session, not the grant.

=item An ID Token can only be used as C<subject_token> when the client is
configured with an asymmetric C<oidcRPMetaDataOptionsIDTokenSignAlg>: an HS*
token is signed with a key the client itself holds.

=item C<resource> must be a single value; several occurrences are refused.

=back

The Resource Authorization Server role -- consuming an ID-JAG through the JWT
Bearer grant -- lives in
L<Lemonldap::NG::Portal::Plugins::OIDCIdentityAssertionGrantServer>.

=head1 HOOKS

This plugin exposes the C<oidcGenerateIdJag> hook, called just before the
assertion is signed:

  use constant hook => { oidcGenerateIdJag => 'addClaimToIdJag' };

  sub addClaimToIdJag {
      my ( $self, $req, $payload, $rp, $target, $sessionInfo ) = @_;
      $payload->{tenant} = $sessionInfo->{tenant};
      return PE_OK;
  }

=head1 SEE ALSO

L<Lemonldap::NG::Portal>,
L<Lemonldap::NG::Portal::Plugins::OIDCIdentityAssertionGrantServer>,
L<Lemonldap::NG::Portal::Lib::OIDCTokenExchange>,
L<https://github.com/linagora/lemonldap-ng-plugins>

=head1 AUTHORS

=over

=item LemonLDAP::NG team L<http://lemonldap-ng.org/team>

=item Xavier Guimard E<lt>yadd@debian.orgE<gt>

=back

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2026 LINAGORA L<https://linagora.com>

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along
with this program. If not, see L<https://www.gnu.org/licenses/>.

=cut
