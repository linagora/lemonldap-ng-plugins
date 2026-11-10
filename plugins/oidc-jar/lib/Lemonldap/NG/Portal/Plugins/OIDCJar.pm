package Lemonldap::NG::Portal::Plugins::OIDCJar;

use strict;
use Digest::SHA qw(sha256_hex);
use Encode qw(encode_utf8);
use JSON;
use LWP::UserAgent;
use Mouse;
use Lemonldap::NG::Common::OpenIDConnect::Constants
  qw(ENC_ALG_SUPPORTED ENC_SUPPORTED);
use Lemonldap::NG::Common::Session;
use Lemonldap::NG::Portal::Main::Constants qw(PE_OK PE_ERROR);

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

our $VERSION = '2.23.0';

use constant hook => {
    oidcGotRequest       => 'processJarRequest',
    oidcGenerateMetadata => 'advertiseJarMetadata',
};

sub init {
    my ($self) = @_;
    return unless $self->SUPER::init;

    # The core fetches a request_uri in exportRequestParameters() (beforeAuth)
    # before our oidcGotRequest hook, including for an unauthenticated
    # request. Route that fetch through the hardened one while this plugin is
    # loaded, so the pre-auth path does not follow redirects either.
    $self->_installCoreFetchGuard;
    return 1;
}

sub _supportedSigAlg {
    my ($self) = @_;
    my @algs = qw/HS256 HS384 HS512/;
    if ( ( $self->conf->{oidcServiceKeyTypeSig} // '' ) eq 'EC' ) {
        push @algs, qw/ES256 ES256K ES384 ES512 EdDSA/;
    }
    else {
        push @algs, qw/RS256 RS384 RS512 PS256 PS384 PS512/;
    }

    # JAR: 'none' is never advertised (RFC 9101 §6.1).
    return \@algs;
}

# Entry point, fires at Issuer/OpenIDConnect.pm:343
sub processJarRequest {
    my ( $self, $req, $oidc_request ) = @_;

    # PAR may call us back after resolving a pushed request, and our own hook
    # may also run afterwards depending on the plugin order.
    return PE_OK if $oidc_request->{_jarRequestProcessed};

    my $client_id = $oidc_request->{client_id};
    return PE_OK unless $client_id;

    my $rp = $self->oidc->getRP($client_id);
    return PE_OK unless $rp;

    # A PAR request_uri is not a request object URI. Leave it to oidc-par,
    # which will call us back on the request it resolved. This keeps JAR
    # working whatever the plugin order.
    if (    $oidc_request->{request_uri}
        and $oidc_request->{request_uri} =~
        /\Aurn:ietf:params:oauth:request_uri:/
        and $self->_parPlugin )
    {
        return PE_OK;
    }

    $oidc_request->{_jarRequestProcessed} = 1;

    my $rpOpts = $self->oidc->rpOptions->{$rp} || {};

    if (   $rpOpts->{oidcRPMetaDataOptionsRequireSignedRequestObject}
        && !$oidc_request->{request}
        && !$oidc_request->{request_uri} )
    {
        return $self->_jarError( $req, $oidc_request, 'request_not_supported',
            'Signed request object is required for this client' );
    }

    if ( my $uri = $oidc_request->{request_uri} ) {
        unless (
            $self->oidc->isUriAllowedForRP(
                $uri, $rp, 'oidcRPMetaDataOptionsRequestUris', 1
            )
          )
        {
            return $self->_jarError( $req, $oidc_request,
                'invalid_request_uri', "request_uri not allowed for $rp" );
        }

        my $jwt = $self->_fetchRequestUri($uri);
        return $self->_jarError( $req, $oidc_request,
            'invalid_request_uri', 'Unable to resolve request_uri' )
          unless defined $jwt;

        $oidc_request->{request} = $jwt;
        delete $oidc_request->{request_uri};
    }

    if ( my $jwt = $oidc_request->{request} ) {
        my $decrypted = $self->_maybeDecrypt($jwt);
        return $self->_jarError( $req, $oidc_request,
            'invalid_request_object', 'Unable to decrypt JAR request object' )
          unless defined $decrypted;
        $oidc_request->{request} = $decrypted;

        my ( $claims, $err ) =
          $self->_extractAndValidateClaims( $req, $decrypted, $rp );
        if ($err) {
            return $self->_jarError( $req, $oidc_request,
                'invalid_request_object', $err );
        }
    }

    return PE_OK;
}

# Verify signature, then validate iss / aud / exp / nbf / iat / jti claims
# as required by RFC 9101 §10.2.
sub _extractAndValidateClaims {
    my ( $self, $req, $jwt, $rp ) = @_;

    my ( $claims, $alg ) = $self->oidc->decodeJWT( $jwt, undef, $rp );
    return ( undef, 'JAR signature verification failed' ) unless defined $claims;
    return ( undef, 'JAR request object payload is not a JSON object' )
      unless ref($claims) eq 'HASH';

    my $expectedAlg =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsJarSigAlg};
    if ( defined $expectedAlg and $expectedAlg ne '' ) {
        return ( undef,
            "Request object alg '$alg' does not match expected '$expectedAlg'" )
          unless defined $alg and $alg eq $expectedAlg;
    }

    my $now  = time;
    my $skew = $self->conf->{oidcJarClockSkew} // 30;

    my $client_id =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};
    if ( defined $claims->{iss} and $claims->{iss} ne $client_id ) {
        return ( undef, "iss claim does not match client_id" );
    }

    if ( defined $claims->{aud} ) {
        my $expected = $self->oidc->get_issuer($req);
        my @auds =
          ref( $claims->{aud} ) eq 'ARRAY'
          ? @{ $claims->{aud} }
          : ( $claims->{aud} );
        unless ( grep { $_ eq $expected } @auds ) {
            return ( undef,
                "aud claim does not match issuer identifier ($expected)" );
        }
    }

    if ( defined $claims->{exp} ) {
        my $exp = $self->_numericDate( $claims->{exp} );
        return ( undef, "exp claim is not a NumericDate" )
          unless defined $exp;
        return ( undef, "Request object is expired" )
          if $exp + $skew < $now;
        $claims->{exp} = $exp;
    }

    if ( defined $claims->{nbf} ) {
        my $nbf = $self->_numericDate( $claims->{nbf} );
        return ( undef, "nbf claim is not a NumericDate" )
          unless defined $nbf;
        return ( undef, "Request object is not yet valid" )
          if $nbf - $skew > $now;
        $claims->{nbf} = $nbf;
    }

    if ( defined $claims->{iat} ) {
        my $iat = $self->_numericDate( $claims->{iat} );
        return ( undef, "iat claim is not a NumericDate" )
          unless defined $iat;
        my $maxAge =
          $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsJarMaxAge};
        if ( $maxAge and $iat + $maxAge + $skew < $now ) {
            return ( undef,
                "Request object iat is older than max age ($maxAge s)" );
        }
        $claims->{iat} = $iat;
    }

    if ( defined $claims->{jti} ) {
        my $jti = $claims->{jti};
        return ( undef, "jti claim must be a non-empty string" )
          if ref $jti or !length $jti;
        my $replay = $self->_checkAndStoreJti( $rp, $claims );
        return ( undef, $replay ) if $replay;
    }

    return ( $claims, undef );
}

# RFC 7519 NumericDate: a finite number. Reject references, NaN, Inf and
# anything that is not a plain decimal number (numeric strings are accepted
# for clients that already send them).
sub _numericDate {
    my ( $self, $value ) = @_;
    return undef if ref $value;
    return undef unless defined $value;
    return undef
      unless $value =~
      /\A-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/;
    my $number = $value + 0;
    return undef unless $number - $number == 0;    # NaN or infinite
    return $number;
}

# Return the loaded PAR server plugin, if any.
sub _parPlugin {
    my ($self) = @_;
    return $self->p->loadedModules
      ->{'Lemonldap::NG::Portal::Plugins::OIDCPushedAuthRequest'};
}

# Anti-replay: a session keyed by sha256(rp . jti) is stored for the lifetime
# of the request object. Any second sighting is a replay.
sub _checkAndStoreJti {
    my ( $self, $rp, $claims ) = @_;

    my $jti = $claims->{jti};

    # Digest::SHA works on bytes only. A jti decoded from a \u escape is a
    # Perl character string and would die with "Wide character" without this.
    my $jtiBytes = utf8::is_utf8($jti) ? encode_utf8($jti) : $jti;
    my $id       = sha256_hex( 'jar-jti:' . $rp . ':' . $jtiBytes );
    my %storeOpts = $self->oidc->_storeOpts();

    my $existing = Lemonldap::NG::Common::Session->new( {
            %storeOpts,
            hashStore => $self->conf->{hashedSessionStore},
            id        => $id,
            kind      => $self->oidc->sessionKind,
        }
    );
    if ( !$existing->error
        and $existing->data
        and defined $existing->data->{jti} )
    {
        return "JAR jti has already been used (replay detected)";
    }

    my $now = time;
    my $ttl =
        ( $claims->{exp} && $claims->{exp} > $now )
      ? ( $claims->{exp} - $now + ( $self->conf->{oidcJarClockSkew} // 30 ) )
      : ( $self->conf->{oidcJarJtiTtl} || 600 );

    my $timeout = $self->conf->{timeout} || 72000;
    my $stored  = Lemonldap::NG::Common::Session->new( {
            %storeOpts,
            hashStore => $self->conf->{hashedSessionStore},
            id        => $id,
            kind      => $self->oidc->sessionKind,
            force     => 1,
            info      => {
                _type  => 'jar_jti',
                _utime => $now + $ttl - $timeout,
                jti    => $jtiBytes,
                rp     => $rp,
            },
        }
    );
    if ( $stored->error ) {
        $self->logger->error(
            "JAR jti anti-replay write failed: " . $stored->error );
        return "Unable to store jti in replay cache";
    }

    return undef;
}

# Download a request_uri, enforcing timeout / Content-Type / size.
# Uses a dedicated UA so the shared OIDC UA is never mutated.
# Wrap the issuer's getRequestJWT once per process. The wrapper resolves the
# plugin instance from the issuer it is called on, so a portal without this
# plugin keeps the core behaviour.
our $coreFetchWrapper;

sub _installCoreFetchGuard {
    my ($self) = @_;

    my $issuer = $self->oidc or return;
    my $pkg    = ref($issuer)   or return;
    my $orig   = $pkg->can('getRequestJWT') or return;
    return 1 if $coreFetchWrapper and $orig == $coreFetchWrapper;

    my $wrapper;
    $wrapper = sub {
        my ( $issuer, $uri ) = @_;
        my $jar = eval {
            $issuer->p->loadedModules
              ->{'Lemonldap::NG::Portal::Plugins::OIDCJar'};
        };
        return $jar->_fetchRequestUri($uri) if $jar;
        return $orig->( $issuer, $uri );
    };

    no strict 'refs';
    no warnings 'redefine';
    *{"${pkg}::getRequestJWT"} = $wrapper;
    $coreFetchWrapper = $wrapper;
    return 1;
}

sub _fetchRequestUri {
    my ( $self, $uri ) = @_;

    my $timeout = $self->conf->{oidcJarRequestUriTimeout} || 10;
    my $max     = $self->conf->{oidcJarRequestUriMaxSize} || 65536;

    # Never follow a redirect: only the URL checked against the RP allowlist
    # may be contacted, and a 302 is not a request object. max_size bounds
    # the raw response before it is read; the decoded size is checked below.
    my $ua = LWP::UserAgent->new(
        timeout      => $timeout,
        max_redirect => 0,
        max_size     => $max,
    );

    my $resp = eval {
        $ua->get(
            $uri,
            Accept => 'application/oauth-authz-req+jwt, application/jwt',
            'Accept-Encoding' => 'identity',
        );
    };
    my $err = $@;

    if ( $err or !$resp ) {
        $self->logger->error("JAR request_uri fetch error: $err");
        return undef;
    }
    unless ( $resp->is_success ) {
        $self->logger->error(
            "JAR request_uri fetch failed: " . $resp->status_line );
        return undef;
    }

    my $ct = $resp->content_type // '';
    unless ( $ct =~ m{^application/(?:oauth-authz-req\+)?jwt\b}i ) {
        $self->logger->error("JAR request_uri unexpected Content-Type: $ct");
        return undef;
    }

    # A request object is a few KB and never needs compression: reading a
    # compressed body would decompress it in memory before the size check.
    my $ce = $resp->header('Content-Encoding') // '';
    if ( length $ce and lc($ce) ne 'identity' ) {
        $self->logger->error(
            "JAR request_uri unexpected Content-Encoding: $ce" );
        return undef;
    }

    # LWP marks a response cut by max_size in Client-Aborted but still
    # reports it as a success.
    if ( my $aborted = $resp->header('Client-Aborted') ) {
        $self->logger->error( "JAR request_uri response aborted ($aborted):"
              . " size limit $max reached" );
        return undef;
    }

    my $body = $resp->content // '';
    if ( length($body) > $max ) {
        $self->logger->error( "JAR request_uri response size "
              . length($body)
              . " exceeds limit $max" );
        return undef;
    }

    # Strip leading/trailing whitespace (some servers wrap the JWT)
    $body =~ s/\A\s+|\s+\z//g;
    return $body;
}

# If $jwt is a JWE (5 segments), decrypt it with the OP's private key.
# Returns a JWS, or undef on failure.
sub _maybeDecrypt {
    my ( $self, $jwt ) = @_;
    my $parts = ( $jwt =~ tr/.// );
    return $jwt if $parts == 2;    # 3 segments -> JWS, nothing to do
    if ( $parts == 4 ) {           # 5 segments -> JWE
        my $decoded = $self->oidc->decryptJwt($jwt);
        return ( defined $decoded and $decoded ne $jwt ) ? $decoded : undef;
    }
    $self->logger->error(
        "JAR request object has unexpected segment count: " . ( $parts + 1 ) );
    return undef;
}

# Translate an internal failure to an RFC 9101 error redirect when we have
# a usable redirect_uri, otherwise fall back to a portal error page.
sub _jarError {
    my ( $self, $req, $oidc_request, $error, $description ) = @_;

    $self->logger->error("JAR error [$error]: $description");

    my $redirect_uri = $oidc_request->{redirect_uri};
    my $client_id    = $oidc_request->{client_id};
    my $state        = $oidc_request->{state};

    if ( $client_id and $redirect_uri ) {
        my $rp = $self->oidc->getRP($client_id);
        if (
            $rp
            and $self->oidc->isUriAllowedForRP(
                $redirect_uri, $rp, 'oidcRPMetaDataOptionsRedirectUris'
            )
          )
        {
            return $self->oidc->returnRedirectError( $req, $redirect_uri,
                $error, $description, undef, $state, 0 );
        }
    }

    $req->data->{_oidcJarError}            = $error;
    $req->data->{_oidcJarErrorDescription} = $description;
    return PE_ERROR;
}

# Extend discovery metadata with RFC 9101 algorithms.
sub advertiseJarMetadata {
    my ( $self, $req, $metadata ) = @_;

    $metadata->{request_object_signing_alg_values_supported} =
      $self->_supportedSigAlg;
    $metadata->{request_object_encryption_alg_values_supported} =
      ENC_ALG_SUPPORTED;
    $metadata->{request_object_encryption_enc_values_supported} = ENC_SUPPORTED;
    $metadata->{require_signed_request_object} =
      $self->_anyRpRequiresSignedRequestObject ? JSON::true : JSON::false;

    return PE_OK;
}

sub _anyRpRequiresSignedRequestObject {
    my ($self) = @_;
    my $rpOpts = $self->conf->{oidcRPMetaDataOptions} || {};
    for my $rp ( keys %$rpOpts ) {
        return 1
          if $rpOpts->{$rp}->{oidcRPMetaDataOptionsRequireSignedRequestObject};
    }
    return 0;
}

1;
__END__

=head1 NAME

Lemonldap::NG::Portal::Plugins::OIDCJar - RFC 9101 (JAR) server-side support

=head1 DESCRIPTION

Adds JWT-Secured Authorization Request (JAR, RFC 9101) capabilities to the
LemonLDAP::NG OpenID Connect issuer:

=over

=item * Decrypts JWE-wrapped Request Objects using the OP service encryption
key before signature verification by the core (F<Lib/OpenIDConnect.pm>
C<decodeJWT>).

=item * Performs a hardened fetch of C<request_uri>: configurable timeout,
Content-Type check (C<application/jwt>, C<application/oauth-authz-req+jwt>),
and response size limit.

=item * Enforces
C<oidcRPMetaDataOptionsRequireSignedRequestObject> by rejecting plain
authorization requests with the RFC 9101 C<request_not_supported> error.

=item * Emits the RFC 9101 error codes C<invalid_request_object>,
C<invalid_request_uri> and C<request_not_supported> back to the RP
when a usable C<redirect_uri> is available.

=item * Validates the JAR claims C<iss>, C<aud>, C<exp>, C<nbf>,
C<iat> (with per-RP C<oidcRPMetaDataOptionsJarMaxAge>) and C<jti>
(anti-replay cache backed by the OpenID Connect session store). The
clock skew is configurable globally via C<oidcJarClockSkew>.

=item * Advertises
C<request_object_signing_alg_values_supported>,
C<request_object_encryption_alg_values_supported>,
C<request_object_encryption_enc_values_supported> and
C<require_signed_request_object> in the discovery document.

=back

=cut
