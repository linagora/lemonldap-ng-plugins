##@file
# Shared plumbing for the "ldap-rest" backends
# (https://github.com/linagora/ldap-rest).
#
# ldap-rest is a lightweight directory manager exposing an LDAP directory
# through a REST API, with consistency plugins, hooks and its own
# authorization layer. This package holds everything the
# Password::LdapRest and Register::LdapRest backends have in common:
#
#   * configuration reading and validation (initLdapRest)
#   * URL building for the "flat resource" endpoints
#   * optional client side password hashing
#   * the "core/auth/token" and "core/auth/hmac" Authorization headers
#   * the low level HTTP call
#
# It is not a backend by itself and is never loaded by the portal directly.
package Lemonldap::NG::Portal::Lib::LdapRest;

use strict;
use Mouse;
use Encode qw(encode);
use JSON;
use MIME::Base64 qw(encode_base64);
use Digest::SHA  qw(sha1 sha256 sha512 sha256_hex hmac_sha256_hex);
use Time::HiRes  ();
use URI;
use URI::Escape qw(uri_escape);
use HTTP::Request;

extends 'Lemonldap::NG::Portal::Lib::REST';

our $VERSION = '0.1.0';

# Optional client side hashing. When no scheme is configured, the cleartext
# password is sent to ldap-rest which forwards it to the directory: this is
# what you want when the LDAP server hashes it itself (OpenLDAP ppolicy with
# "ppolicy_hash_cleartext", or a "pw-*" overlay).
our %hashSchemes = (
    SHA     => { digest => \&sha1,   salted => 0 },
    SHA256  => { digest => \&sha256, salted => 0 },
    SHA512  => { digest => \&sha512, salted => 0 },
    SSHA    => { digest => \&sha1,   salted => 1 },
    SSHA256 => { digest => \&sha256, salted => 1 },
    SSHA512 => { digest => \&sha512, salted => 1 },
);

# PROPERTIES

# Base URL of the ldap-rest service, without trailing slash
has restBase => ( is => 'rw' );

# Plural resource name handled by ldap-rest (users, mailgroups, ...)
has restResource => ( is => 'rw', default => 'users' );

# ldap-rest "mainAttribute" of that resource: the attribute building the RDN
has restMainAttr => ( is => 'rw', default => 'uid' );

# none|token|hmac
has restAuth => ( is => 'rw', default => 'none' );

has pwdAttr => ( is => 'rw', default => 'userPassword' );

# Empty string means "no client side hashing"
has hashScheme => ( is => 'rw', default => '' );

# JSON encoder producing exactly what JSON.stringify() would produce on the
# ldap-rest side: this is required by the HMAC plugin which recomputes the
# body hash from the *parsed* body
has json => (
    is      => 'ro',
    lazy    => 1,
    default => sub { JSON->new->utf8->canonical(0) }
);

# INITIALIZATION

# Read and validate the ldapRest* configuration keys. Returns 0 (and logs)
# on any misconfiguration, so that callers can propagate the failure to
# their own init().
sub initLdapRest {
    my ($self) = @_;

    my $url = $self->conf->{ldapRestUrl};
    unless ($url) {
        $self->logger->error('Missing "ldapRestUrl" parameter');
        return 0;
    }
    $url =~ s#/+$##;
    $self->restBase($url);

    my $resource = $self->conf->{ldapRestResource} || 'users';
    $resource =~ s#^/+|/+$##g;
    $self->restResource($resource);

    $self->restMainAttr( $self->conf->{ldapRestMainAttribute} || 'uid' );

    $self->pwdAttr( $self->conf->{ldapRestPasswordAttribute}
          || 'userPassword' );

    my $scheme = uc( $self->conf->{ldapRestPasswordHash} || '' );
    if ( $scheme and not $hashSchemes{$scheme} ) {
        $self->logger->error("Unknown password hash scheme: $scheme");
        return 0;
    }
    $self->hashScheme($scheme);

    my $auth = $self->conf->{ldapRestAuthMode} || 'none';
    if ( $auth eq 'token' ) {
        unless ( $self->conf->{ldapRestToken} ) {
            $self->logger->error(
                'Missing "ldapRestToken" parameter (token authentication)');
            return 0;
        }
    }
    elsif ( $auth eq 'hmac' ) {
        unless ($self->conf->{ldapRestHmacId}
            and $self->conf->{ldapRestHmacSecret} )
        {
            $self->logger->error(
'Missing "ldapRestHmacId" or "ldapRestHmacSecret" parameter (HMAC authentication)'
            );
            return 0;
        }
    }
    elsif ( $auth ne 'none' ) {
        $self->logger->error("Unknown ldap-rest authentication mode: $auth");
        return 0;
    }
    $self->restAuth($auth);

    return 1;
}

# URL BUILDING

# Collection endpoint: list (GET) and create (POST)
sub _collectionPath {
    my ($self) = @_;
    return '/api/v1/ldap/' . uri_escape( $self->restResource );
}

# Single entry endpoint: get (GET), modify (PUT), delete (DELETE)
sub _entryPath {
    my ( $self, $id ) = @_;
    return $self->_collectionPath . '/' . uri_escape($id);
}

# ldap-rest answers {"success":true} on modify/delete and the entry itself
# on get/create: stay tolerant and only reject an explicit failure.
sub _isSuccess {
    my ( $self, $res ) = @_;
    return 0 unless ref $res eq 'HASH';
    return 1 unless exists $res->{success};
    return $res->{success} ? 1 : 0;
}

# PASSWORD HASHING

sub hashPassword {
    my ( $self, $pwd ) = @_;
    my $scheme = $self->hashScheme;
    return $pwd unless $scheme;

    my $def = $hashSchemes{$scheme}
      or do {
        $self->logger->error("Unknown password hash scheme: $scheme");
        return undef;
      };

    my $bytes = encode( 'UTF-8', $pwd );
    my $salt  = '';
    if ( $def->{salted} ) {
        $salt = eval { require Crypt::URandom; Crypt::URandom::urandom(8) };
        if ($@) {
            $self->logger->error("Unable to generate salt: $@");
            return undef;
        }
    }
    my $digest = $def->{digest}->( $bytes . $salt );
    return "{$scheme}" . encode_base64( $digest . $salt, '' );
}

# LOW LEVEL REST CALLS

# Send $content (encoded as JSON) to ldap-rest and return the raw
# HTTP::Response, whatever its status. Dies on transport error only, so that
# callers able to make sense of a status (typically a 404 on a lookup) can
# do so. Never logs the body: it may contain a password.
sub ldapRestRequest {
    my ( $self, $method, $path, $content ) = @_;
    $method = uc $method;

    my $url  = $self->restBase . $path;
    my $body = defined $content ? $self->json->encode($content) : '';

    $self->logger->debug("ldap-rest: $method $url");

    my $hreq = HTTP::Request->new( $method => $url );
    $hreq->header( Accept => 'application/json' );
    if ( length $body ) {
        $hreq->header( 'Content-Type' => 'application/json' );
        $hreq->content($body);
    }
    $self->setAuthorization( $hreq, $method, $url, $body );

    return $self->ua->request($hreq);
}

# Same as ldapRestRequest() but returns the decoded answer and dies on any
# HTTP error.
sub ldapRestCall {
    my ( $self, $method, $path, $content ) = @_;

    my $resp = $self->ldapRestRequest( $method, $path, $content );
    unless ( $resp->is_success ) {
        die $self->ldapRestError($resp);
    }

    return $self->ldapRestDecode($resp);
}

# Build a one line error message out of a failed response
sub ldapRestError {
    my ( $self, $resp ) = @_;
    my $detail = eval { $resp->decoded_content } || '';
    $detail =~ s/\s+/ /g;
    return $resp->status_line . ( $detail ? " ($detail)" : '' );
}

# Decode a JSON answer. Dies if the body is not a JSON object.
sub ldapRestDecode {
    my ( $self, $resp ) = @_;

    # 204 and friends: nothing to decode, the HTTP status is the answer
    return {} unless length( $resp->content );

    my $res = eval { $self->json->decode( $resp->content ) };
    die "Bad ldap-rest response: $@" if $@;
    die "Bad ldap-rest response: expecting a JSON HASH, got " . ref($res)
      if ref($res) ne 'HASH';

    return $res;
}

# Set the "Authorization" header expected by the ldap-rest auth plugin
sub setAuthorization {
    my ( $self, $hreq, $method, $url, $body ) = @_;
    my $mode = $self->restAuth;
    return if ( !$mode or $mode eq 'none' );

    if ( $mode eq 'token' ) {

        # core/auth/token
        $hreq->header(
            Authorization => 'Bearer ' . $self->conf->{ldapRestToken} );
        return;
    }

    # core/auth/hmac:
    #   Authorization: HMAC-SHA256 <service-id>:<timestamp>:<signature>
    #   signature = HMAC-SHA256(secret, "METHOD|PATH|timestamp|body-hash")
    #   body-hash = sha256_hex(body), empty for GET/DELETE/HEAD
    # PATH is the path (with query string) seen by ldap-rest: keep the
    # reverse proxy (if any) path-preserving.
    my $timestamp  = int( Time::HiRes::time() * 1000 );
    my $uri        = URI->new($url);
    my $signedPath = $uri->path_query;
    my $bodyHash =
      ( $method =~ /^(?:GET|DELETE|HEAD)$/ or !length $body )
      ? ''
      : sha256_hex($body);
    my $signature = hmac_sha256_hex(
        join( '|', $method, $signedPath, $timestamp, $bodyHash ),
        encode( 'UTF-8', $self->conf->{ldapRestHmacSecret} )
    );
    $hreq->header( Authorization => 'HMAC-SHA256 '
          . $self->conf->{ldapRestHmacId}
          . ":$timestamp:$signature" );
}

1;
