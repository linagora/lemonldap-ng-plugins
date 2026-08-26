# Resource Authorization Server side of the Identity Assertion JWT
# Authorization Grant (ID-JAG), also known as Cross-App Access (XAA).
#
# See draft-ietf-oauth-identity-assertion-authz-grant
#
# Where OIDCIdentityAssertionGrant.pm *issues* assertions (the Identity
# Provider Authorization Server role), this module *consumes* them: a client
# holding an ID-JAG minted by a trusted identity provider presents it on the
# token endpoint with the RFC 7523 JWT Bearer grant, and gets a local access
# token for the APIs this LemonLDAP::NG protects.
package Lemonldap::NG::Portal::Plugins::OIDCIdentityAssertionGrantServer;

use strict;
use Mouse;
use Digest::SHA qw(sha256_hex);
use Lemonldap::NG::Common::JWT qw(getJWTHeader getJWTPayload);
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_SENDRESPONSE
);

our $VERSION = '0.1.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

use constant JWT_BEARER_GRANT =>
  'urn:ietf:params:oauth:grant-type:jwt-bearer';
use constant ID_JAG_TYP        => 'oauth-id-jag+jwt';
use constant RAR_SESSION_KEY   => '_rar_details';
use constant JTI_INDEX_PREFIX  => 'idjag-jti:';

# INTERFACE
use constant hook => {
    oidcGotTokenRequest  => 'handleJwtBearerGrant',
    oidcGenerateMetadata => 'advertiseJwtBearer',
};

# OpenID Connect Provider metadata (issuer, JWKS) is loaded by
# Auth::OpenIDConnect / UserDB::OpenIDConnect only, i.e. when LemonLDAP::NG is
# an OIDC *client*. A Resource Authorization Server usually is not, so load it
# here -- once per instance, and lazily, because the issuer module may not be
# registered yet when plugins are initialized.
has _opsLoaded => ( is => 'rw', default => 0 );

sub loadTrustedOps {
    my ($self) = @_;
    return if $self->_opsLoaded;
    $self->_opsLoaded(1);
    $self->oidc->loadOPs;
    return;
}

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

# Entry point: called for every token endpoint request.
sub handleJwtBearerGrant {
    my ( $self, $req, $rp, $grant_type ) = @_;
    return PE_OK unless $grant_type eq JWT_BEARER_GRANT;

    $self->logger->debug("JWT Bearer grant presented by RP $rp");
    $req->response( $self->_run( $req, $rp ) );
    return PE_SENDRESPONSE;
}

# Advertise the grant in /.well-known/openid-configuration.
sub advertiseJwtBearer {
    my ( $self, $req, $metadata ) = @_;

    return PE_OK unless $self->_anyTrustedOp;

    my $grants = $metadata->{grant_types_supported} ||= [];
    push @$grants, JWT_BEARER_GRANT
      unless grep { $_ eq JWT_BEARER_GRANT } @$grants;

    return PE_OK;
}

sub _anyTrustedOp {
    my ($self) = @_;
    my $opOptions = $self->conf->{oidcOPMetaDataOptions} || {};
    return scalar
      grep { $_->{oidcOPMetaDataOptionsAllowIdJagGrant} } values %$opOptions;
}

sub _run {
    my ( $self, $req, $rp ) = @_;
    my $oidc = $self->oidc;

    # 1. The presenting client must be explicitly allowed
    unless (
        $oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsAllowIdJagBearer} )
    {
        $self->userLogger->error(
            "JWT Bearer grant is not allowed for RP $rp");
        return $oidc->sendOIDCError( $req, 'unauthorized_client', 400 );
    }

    my $assertion = $req->param('assertion');
    unless ($assertion) {
        $self->logger->error('JWT Bearer grant without assertion');
        return $oidc->sendOIDCError( $req, 'invalid_request', 400,
            'assertion is required' );
    }

    # 2. Only ID-JAG assertions are accepted here. Refusing anything else by
    #    its `typ` keeps this grant from becoming a generic JWT bearer path.
    my $header = eval { getJWTHeader($assertion) } || {};
    unless ( ( $header->{typ} || '' ) eq ID_JAG_TYP ) {
        $self->userLogger->error( 'JWT Bearer assertion is not an ID-JAG (typ '
              . ( $header->{typ} || 'missing' )
              . ')' );
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }

    # The assertion is verified against the JWKS of the issuing identity
    # provider: symmetric and unsigned assertions have no place here.
    my $alg = $header->{alg} || '';
    if ( !$alg or $alg eq 'none' or $alg =~ /^HS/ ) {
        $self->userLogger->error(
            "ID-JAG must be signed with an asymmetric algorithm, got "
              . ( $alg || 'nothing' ) );
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }

    # 3. Resolve the issuer into a trusted identity provider, *before* any
    #    signature check, so we know which JWKS to verify against.
    my $unverified = eval { getJWTPayload($assertion) } || {};
    my $iss = $unverified->{iss};
    unless ($iss) {
        $self->userLogger->error('ID-JAG without iss claim');
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }
    my $op = $self->_findTrustedOp($iss);
    unless ($op) {
        $self->userLogger->error(
            "ID-JAG issued by an untrusted identity provider: $iss");
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }

    # 4. Verify the signature against that provider's JWKS
    my $claims = $oidc->decodeJWT( $assertion, $op );
    unless ($claims) {
        $self->userLogger->error("Unable to verify ID-JAG issued by $iss");
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }

    # decodeJWT() picks the key, not the issuer: re-check iss on the verified
    # payload so a swapped claim cannot slip through the unverified read above.
    unless ( ( $claims->{iss} || '' ) eq
        ( $oidc->opMetadata->{$op}->{conf}->{issuer} || '' ) )
    {
        $self->userLogger->error(
            "ID-JAG iss does not match the issuer declared by $op");
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }

    # 5. This assertion must be addressed to us
    my $audience = $self->_ourAudience($req);
    unless ( grep { $_ eq $audience }
        ( ref $claims->{aud} eq 'ARRAY' ? @{ $claims->{aud} } : ( $claims->{aud} // () ) ) )
    {
        $self->userLogger->error(
            "ID-JAG is not addressed to $audience");
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }

    # 6. Freshness
    my $skew = $self->conf->{oidcServiceIdJagAllowedSkew} // 30;
    my $now  = time;
    unless ( $claims->{exp} and $claims->{exp} + $skew > $now ) {
        $self->userLogger->error('ID-JAG is expired');
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }
    if ( $claims->{nbf} and $claims->{nbf} - $skew > $now ) {
        $self->userLogger->error('ID-JAG is not valid yet');
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }
    if ( $claims->{iat} and $claims->{iat} - $skew > $now ) {
        $self->userLogger->error('ID-JAG was issued in the future');
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }

    # 7. The assertion must have been minted for the client presenting it
    my $clientId = $oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};
    unless ( ( $claims->{client_id} || '' ) eq ( $clientId // '' ) ) {
        $self->userLogger->error(
            "ID-JAG was not issued for client $clientId");
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }

    # 8. Single use
    unless ( $claims->{jti} ) {
        $self->userLogger->error('ID-JAG without jti claim');
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }
    unless ( $self->_consumeJti( $claims->{iss}, $claims->{jti},
            $claims->{exp} + $skew - $now ) )
    {
        $self->userLogger->error(
            "ID-JAG $claims->{jti} was already used");
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }

    # 9. Map the asserted subject onto a local identity
    my $attr = $self->opOptions->{$op}->{oidcOPMetaDataOptionsIdJagUserAttribute}
      || 'sub';
    my $user = $claims->{$attr};
    unless ( defined $user and $user ne '' ) {
        $self->userLogger->error("ID-JAG has no $attr claim");
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }

    my $sessionInfo = $self->_lookupUser( $req, $user, $op );
    unless ($sessionInfo) {
        $self->userLogger->error(
            "ID-JAG subject $user is unknown to this server");
        return $oidc->sendOIDCError( $req, 'invalid_grant', 400 );
    }

    # 10. Local policy has the last word
    my $scope = $self->_grantedScope( $req, $rp, $claims );
    unless ($scope) {
        $self->userLogger->warn(
            "No scope granted to $user for RP $rp during JWT Bearer grant");
        return $oidc->sendOIDCError( $req, 'invalid_scope', 400 );
    }

    $req->userData($sessionInfo);
    if ( my $rule = $oidc->rpRules->{$rp} ) {
        my $ruleVariables = { %$sessionInfo, _oidc_grant_type => 'idjag' };
        unless ( $rule->( $req, $ruleVariables ) ) {
            $self->userLogger->warn(
                    "User $user did not validate the access rule of "
                  . "relying party $rp during JWT Bearer grant" );
            return $oidc->sendOIDCError( $req, 'access_denied', 400 );
        }
    }

    # 11. Mint the local access token
    my $session =
      $self->p->getApacheSession( undef, info => $sessionInfo, kind => 'SSO' );
    unless ($session) {
        $self->logger->error('Unable to create session');
        return $oidc->sendOIDCError( $req, 'server_error', 500 );
    }

    my $extra = {
        scope           => $scope,
        rp              => $rp,
        user_session_id => $session->id,
        grant_type      => 'idjag',
        _idjag_iss      => $claims->{iss},
    };

    # Carry RFC 9396 authorization_details of the assertion onto the access
    # token session, so oidc-rar surfaces them on introspection.
    $extra->{ &RAR_SESSION_KEY } = $claims->{authorization_details}
      if ref( $claims->{authorization_details} ) eq 'ARRAY';

    my $access_token =
      $oidc->newAccessToken( $req, $rp, $scope, $session->data, $extra );
    unless ($access_token) {
        $self->userLogger->error('Unable to create Access Token');
        return $oidc->sendOIDCError( $req, 'server_error', 500 );
    }

    my $expires_in =
         $oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsAccessTokenExpiration}
      || $self->conf->{oidcServiceAccessTokenExpiration}
      || 3600;

    $self->auditLog(
        $req,
        code    => 'ISSUER_OIDC_ID_JAG_ACCEPTED',
        rp      => $rp,
        message => "RP $rp exchanged an ID-JAG issued by $claims->{iss} "
          . "for an access token (user $user)",
        user => $sessionInfo->{ $self->conf->{whatToTrace} },
    );

    return $self->p->sendJSONresponse(
        $req,
        {
            access_token => "$access_token",
            token_type   => 'Bearer',
            expires_in   => $expires_in + 0,
            scope        => "$scope",
            (
                ref( $claims->{authorization_details} ) eq 'ARRAY'
                ? ( authorization_details => $claims->{authorization_details} )
                : ()
            ),
        }
    );
}

# Identifier remote identity providers must put in the `aud` claim. Defaults
# to our own issuer, which is what they would naturally use.
sub _ourAudience {
    my ( $self, $req ) = @_;
    return $self->conf->{oidcServiceIdJagAudience}
      || $self->oidc->get_issuer($req);
}

# Find the declared OP whose issuer matches, among those allowed to issue
# ID-JAGs for us.
sub _findTrustedOp {
    my ( $self, $iss ) = @_;
    my $oidc = $self->oidc;
    $self->loadTrustedOps;

    my ($op) = grep {
             $self->opOptions->{$_}->{oidcOPMetaDataOptionsAllowIdJagGrant}
          and ( $oidc->opMetadata->{$_}->{conf}->{issuer} || '' ) eq $iss
    } sort keys %{ $oidc->opMetadata || {} };

    return $op;
}

sub opOptions {
    my ($self) = @_;
    return $self->oidc->opOptions || {};
}

# Single-use enforcement. The jti is recorded under a fixed session id for as
# long as the assertion could still be replayed; a second presentation finds
# the record and is refused.
sub _consumeJti {
    my ( $self, $iss, $jti, $ttl ) = @_;
    $ttl = 300 if !$ttl or $ttl < 1;

    my $id = sha256_hex( JTI_INDEX_PREFIX . $iss . '|' . $jti );

    my $existing = $self->p->getApacheSession(
        $id,
        kind      => $self->oidc->sessionKind,
        noInfo    => 1,
        hashStore => 0,
    );
    return 0 if $existing;

    my $session = $self->p->getApacheSession(
        $id,
        kind => $self->oidc->sessionKind,
        info => {
            _type  => 'idjag_jti',
            _utime => time() - $self->conf->{timeout} + $ttl,
            iss    => $iss,
            jti    => $jti,
        },
        force     => 1,
        hashStore => 0,
    );
    unless ($session) {
        $self->logger->error("Unable to record ID-JAG jti $jti");
        return 0;
    }
    return 1;
}

# Resolve the asserted subject through the local user backends. There is no
# interactive authentication here: the identity provider already vouched for
# the user, we only need this server's own view of them.
sub _lookupUser {
    my ( $self, $req, $user, $op ) = @_;

    $req->user($user);
    $req->sessionInfo( {} );
    $req->steps(
        [ 'getUser', 'setSessionInfo', $self->groupsAndMacros,
            'setLocalGroups' ] );

    # Tell Lib::Choice which sub-module to use, as there is no interactive
    # auth flow in progress to pick one.
    if ( my $choice = $self->conf->{oidcServiceIdJagChoice} ) {
        $req->data->{_authChoice} = $choice;
    }

    my $error = $self->p->process($req);
    if ( $error != PE_OK ) {
        $self->logger->info(
            "ID-JAG: user '$user' not found (error: $error)");
        return;
    }

    my $sessionInfo = $req->sessionInfo || {};
    $sessionInfo->{_idjag_op}  = $op;
    $sessionInfo->{_utime}   ||= time;
    return $sessionInfo;
}

# The scope of the issued access token: what the client asks for, bounded by
# what the assertion grants, then by this RP policy.
sub _grantedScope {
    my ( $self, $req, $rp, $claims ) = @_;

    my $asserted  = $claims->{scope} || '';
    my $requested = $req->param('scope') || $asserted;

    if ($asserted) {
        my %granted = map { $_ => 1 } grep { length } split /\s+/, $asserted;
        my @kept = grep { $granted{$_} } grep { length } split /\s+/,
          $requested;
        $requested = join ' ', @kept;
        return unless $requested;
    }

    return $self->oidc->getScope( $req, $rp, $requested );
}

1;
__END__

=pod

=encoding utf8

=head1 NAME

Lemonldap::NG::Portal::Plugins::OIDCIdentityAssertionGrantServer - Resource
Authorization Server side of ID-JAG / Cross-App Access

=head1 DESCRIPTION

This plugin implements the Resource Authorization Server role of
L<draft-ietf-oauth-identity-assertion-authz-grant|https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/>.

A client holding an B<ID-JAG> minted by a trusted identity provider presents
it on the token endpoint using the RFC 7523 JWT Bearer grant, and receives a
local access token:

  POST /oauth2/token
  Authorization: Basic ...

  grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
  &assertion=<ID-JAG>
  &scope=...

The assertion is checked for: an C<oauth-id-jag+jwt> type header, an
asymmetric signature verified against the JWKS of the issuing provider, an
C<iss> matching a trusted provider, an C<aud> naming this server, freshness,
a C<client_id> matching the authenticated client, and a C<jti> that has not
been seen before.

The asserted subject is then resolved through the local user backends -- no
interactive authentication takes place -- and the relying party access rule
is evaluated before the access token is issued.

=head1 CONFIGURATION

On the B<trusted identity provider>, declared as an OpenID Connect provider
(I<OpenID Connect Providers> in the Manager):

=over

=item C<oidcOPMetaDataOptionsAllowIdJagGrant>: accept ID-JAGs issued by this
provider (also loads this plugin).

=item C<oidcOPMetaDataOptionsIdJagUserAttribute>: claim carrying the local
user identifier, defaults to C<sub>.

=back

On the B<presenting client>:

=over

=item C<oidcRPMetaDataOptionsAllowIdJagBearer>: allow this client to exchange
an ID-JAG for an access token.

=back

Globally:

=over

=item C<oidcServiceIdJagAudience>: identifier remote providers must send as
C<aud>. Defaults to our own issuer.

=item C<oidcServiceIdJagAllowedSkew>: clock skew tolerance in seconds,
defaults to 30.

=item C<oidcServiceIdJagChoice>: name of the C<authChoiceModules> entry to use
for the user lookup when the server runs C<Auth = Choice>.

=back

=head1 SEE ALSO

L<Lemonldap::NG::Portal>,
L<Lemonldap::NG::Portal::Plugins::OIDCIdentityAssertionGrant>,
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
