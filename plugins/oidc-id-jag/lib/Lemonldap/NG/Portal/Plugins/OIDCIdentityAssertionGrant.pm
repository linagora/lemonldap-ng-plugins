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

# INTERFACE
use constant hook => {
    oidcGotTokenExchange => 'handleIdentityAssertionGrant',
    oidcGenerateMetadata => 'advertiseIdentityChaining',
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

    # 4. Resolve the subject from the presented token
    my $userData = $self->_getUserData( $req, $rp );
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

    # 6. Narrow down requested scopes using the target RP policy
    my $requestedScope = $req->param('scope') || '';
    my $scope          = $oidc->getScope( $req, $target, $requestedScope );

    # 7. Build and sign the assertion
    my $expiration =
         $oidc->rpOptions->{$target}->{oidcRPMetaDataOptionsIdJagExpiration}
      || $self->conf->{oidcServiceIdJagExpiration}
      || 300;

    my $payload = {
        iss       => $oidc->get_issuer($req),
        sub       => "$sub",
        aud       => "$audience",
        client_id => $self->_clientIdForTarget( $rp, $target ),
        jti       => $oidc->generateNonce,
        iat       => time,
        exp       => time + $expiration,
        ( $scope ? ( scope => "$scope" ) : () ),
        (
            $req->param('resource')
            ? ( resource => $req->param('resource') )
            : ()
        ),
    };

    my $h =
      $self->p->processHook( $req, 'oidcGenerateIdJag', $payload, $rp, $target,
        $userData );
    return $oidc->sendOIDCError( $req, 'server_error', 500 ) if ( $h != PE_OK );

    my $alg = $self->_signatureAlg($target);
    unless ($alg) {
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

# Find the RP declaring $audience as its Authorization Server identifier
sub _findTargetRp {
    my ( $self, $audience ) = @_;
    my $rpOptions = $self->oidc->rpOptions;

    my ($target) = grep {
        ( $rpOptions->{$_}->{oidcRPMetaDataOptionsIdJagAudience} || '' ) eq
          $audience
    } sort keys %$rpOptions;

    return $target;
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

# Resolve the subject_token into user session data.
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

    my $tokenSession;
    if ( $type eq 'id_token' ) {
        $tokenSession = $self->_getSessionFromIdToken( $rp, $subjectToken );
    }
    elsif ( $type eq 'refresh_token' ) {
        $tokenSession = $oidc->getRefreshToken($subjectToken);
    }
    elsif ( $type eq 'access_token' or $type eq '' ) {
        $tokenSession = $oidc->getAccessToken($subjectToken);
    }
    else {
        $self->userLogger->error(
            "Unsupported subject_token_type for ID-JAG: $type");
        return;
    }

    unless ($tokenSession) {
        $self->userLogger->error('Unable to validate ID-JAG subject_token');
        return;
    }

    # The subject_token MUST have been issued to the authenticated client
    my $clientId = $oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};
    my $tokenClientId = $tokenSession->data->{client_id} || '';
    my $tokenRp       = $tokenSession->data->{rp}        || '';
    unless ( $tokenClientId eq $clientId or $tokenRp eq $rp ) {
        $self->userLogger->error(
            "ID-JAG subject_token was not issued to client $clientId");
        return;
    }

    # Online tokens are tied to a SSO session, offline ones embed a copy of
    # the user attributes
    my $sessionId = $tokenSession->data->{user_session_id};
    unless ($sessionId) {
        return $tokenSession->data
          if $tokenSession->data->{ $self->conf->{whatToTrace} };
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

    return $userData;
}

# Resolve an ID Token issued by this OP into the refresh token session which
# carries the same `sid`
sub _getSessionFromIdToken {
    my ( $self, $rp, $idToken ) = @_;
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

    my $sid = $payload->{sid};
    unless ($sid) {
        $self->userLogger->error('ID Token has no sid claim');
        return;
    }

    my %opts    = $oidc->_storeOpts;
    my $options = $opts{storageModuleOptions};
    $options->{backend} = $opts{storageModule};

    my $sessions = Lemonldap::NG::Common::Apache::Session->searchOn( $options,
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
        return $session if $session;
    }

    $self->userLogger->error("No session found for ID Token sid $sid");
    return;
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

=back

=head1 LIMITATIONS

The draft is not stabilized yet, and this implementation covers the Identity
Provider side only:

=over

=item When an ID Token is used as C<subject_token>, the user session is
resolved through its C<sid> claim, which is only stored in refresh token
sessions: the client must be allowed to get refresh tokens.

=item C<authorization_details> is not forwarded.

=item Consuming an ID-JAG through the JWT Bearer grant (Resource Authorization
Server role) is not implemented.

=back

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
