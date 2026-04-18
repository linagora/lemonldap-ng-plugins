use warnings;
use Test::More;
use strict;
use IO::String;
use LWP::UserAgent;
use LWP::Protocol::PSGI;
use Plack::Request;
use Plack::Response;
use MIME::Base64 qw(encode_base64url);
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

eval { require Crypt::JWT };
if ($@) {
    plan skip_all => 'Crypt::JWT unavailable';
}
Crypt::JWT->import(qw(encode_jwt));

my $debug = 'error';
my $op    = op();
my $i = $op->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};

# Shared state used by the mock request_uri HTTP server.
our %mockResponse = (
    body         => undef,
    content_type => 'application/jwt',
    status       => 200,
);

LWP::Protocol::PSGI->register(
    sub {
        my $req = Plack::Request->new(@_);
        is( $req->uri->host, 'request.uri', 'only authorized URI is called' );

        my $res = Plack::Response->new( $mockResponse{status} );
        $res->content_type( $mockResponse{content_type} );
        $res->body( defined $mockResponse{body} ? $mockResponse{body} : '' );
        return $res->finalize;
    }
);

# Helpers -------------------------------------------------------------------

sub signedRequestObject {
    my ($payload) = @_;
    return $i->createJWT( $payload, 'HS256', 'rp' );
}

sub encryptedRequestObject {
    my ($payload) = @_;
    my $signed = signedRequestObject($payload);
    return encode_jwt(
        payload => $signed,
        alg     => 'RSA-OAEP',
        enc     => 'A128CBC-HS256',
        key     => \oidc_cert_op_public_sig(),
    );
}

sub makeAlgNoneJwt {
    my ($payload) = @_;
    my $header =
      encode_base64url( JSON::to_json( { alg => 'none', typ => 'JWT' } ) );
    my $body = encode_base64url( JSON::to_json($payload) );
    return "$header.$body.";
}

# Tests ---------------------------------------------------------------------

subtest 'Signed request object via `request` parameter' => sub {
    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'xxyy',
            request       => signedRequestObject( {
                    client_id    => 'rpid',
                    redirect_uri => 'http://redirect.uri/',
                }
            ),
        }
    );
    expectRedirection( $res, qr,http://redirect.uri/.*state=xxyy, );
};

subtest 'Encrypted + signed request object (JWE wrapping JWS)' => sub {
    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'enc1',
            request       => encryptedRequestObject( {
                    client_id    => 'rpid',
                    redirect_uri => 'http://redirect.uri/',
                }
            ),
        }
    );
    expectRedirection( $res, qr,http://redirect.uri/.*state=enc1, );
};

subtest 'Signed request object via `request_uri`' => sub {
    local %mockResponse = (
        body => signedRequestObject( {
                client_id    => 'rpid',
                redirect_uri => 'http://redirect.uri/',
            }
        ),
        content_type => 'application/jwt',
        status       => 200,
    );

    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'uri1',
            request_uri   => 'http://request.uri/valid',
        }
    );
    expectRedirection( $res, qr,http://redirect.uri/.*state=uri1, );
};

subtest 'request_uri: invalid Content-Type' => sub {
    local %mockResponse = (
        body         => 'foo',
        content_type => 'text/plain',
        status       => 200,
    );

    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'uri2',
            redirect_uri  => 'http://redirect.uri/',
            request_uri   => 'http://request.uri/bad-ctype',
        }
    );
    expectRedirection( $res,
        qr,http://redirect.uri/.*error=invalid_request_uri, );
};

subtest 'request_uri: response too large' => sub {
    local %mockResponse = (
        body         => 'A' x 200_000,
        content_type => 'application/jwt',
        status       => 200,
    );

    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'uri3',
            redirect_uri  => 'http://redirect.uri/',
            request_uri   => 'http://request.uri/too-big',
        }
    );
    expectRedirection( $res,
        qr,http://redirect.uri/.*error=invalid_request_uri, );
};

subtest 'request_uri: HTTP error' => sub {
    local %mockResponse = (
        body         => 'oops',
        content_type => 'text/plain',
        status       => 500,
    );

    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'uri4',
            redirect_uri  => 'http://redirect.uri/',
            request_uri   => 'http://request.uri/boom',
        }
    );
    expectRedirection( $res,
        qr,http://redirect.uri/.*error=invalid_request_uri, );
};

subtest 'require_signed_request_object enforces presence' => sub {
    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'strict',
            scope         => 'openid',
            state         => 'sx',
            redirect_uri  => 'http://redirect.uri/',
        }
    );
    expectRedirection( $res,
        qr,http://redirect.uri/.*error=request_not_supported, );
};

subtest 'Undecryptable JWE yields invalid_request_object' => sub {

    # Random bytes assembled in JWE shape: 5 dot-separated base64url segments.
    my $bogus = join '.',
      map { encode_base64url($_) } ( 'HDR', 'KEY', 'IV', 'CT', 'TAG' );

    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'enc2',
            redirect_uri  => 'http://redirect.uri/',
            request       => $bogus,
        }
    );
    expectRedirection( $res,
        qr,http://redirect.uri/.*error=invalid_request_object, );
};

subtest 'JWS with alg:none is rejected' => sub {
    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'none1',
            redirect_uri  => 'http://redirect.uri/',
            request       => makeAlgNoneJwt( {
                    client_id    => 'rpid',
                    redirect_uri => 'http://redirect.uri/',
                }
            ),
        }
    );

    expectRedirection( $res,
        qr,http://redirect.uri/.*error=invalid_request_object, );
};

subtest 'Valid claims (iss/aud/exp/nbf/iat/jti) are accepted' => sub {
    my $now   = time;
    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'claims1',
            request       => signedRequestObject( {
                    iss          => 'rpid',
                    aud          => 'http://auth.op.com/',
                    exp          => $now + 60,
                    nbf          => $now - 10,
                    iat          => $now,
                    jti          => 'jti-valid-' . $now,
                    client_id    => 'rpid',
                    redirect_uri => 'http://redirect.uri/',
                }
            ),
        }
    );
    expectRedirection( $res, qr,http://redirect.uri/.*state=claims1, );
};

subtest 'iss mismatch is rejected' => sub {
    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'iss1',
            redirect_uri  => 'http://redirect.uri/',
            request       => signedRequestObject( {
                    iss          => 'wrong-client',
                    client_id    => 'rpid',
                    redirect_uri => 'http://redirect.uri/',
                }
            ),
        }
    );
    expectRedirection( $res,
        qr,http://redirect.uri/.*error=invalid_request_object, );
};

subtest 'aud mismatch is rejected' => sub {
    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'aud1',
            redirect_uri  => 'http://redirect.uri/',
            request       => signedRequestObject( {
                    aud          => 'https://other.example.com/',
                    client_id    => 'rpid',
                    redirect_uri => 'http://redirect.uri/',
                }
            ),
        }
    );
    expectRedirection( $res,
        qr,http://redirect.uri/.*error=invalid_request_object, );
};

subtest 'Expired request object is rejected' => sub {
    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'exp1',
            redirect_uri  => 'http://redirect.uri/',
            request       => signedRequestObject( {
                    exp          => time - 3600,
                    client_id    => 'rpid',
                    redirect_uri => 'http://redirect.uri/',
                }
            ),
        }
    );
    expectRedirection( $res,
        qr,http://redirect.uri/.*error=invalid_request_object, );
};

subtest 'Request object not yet valid (nbf in future) is rejected' => sub {
    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'nbf1',
            redirect_uri  => 'http://redirect.uri/',
            request       => signedRequestObject( {
                    nbf          => time + 3600,
                    client_id    => 'rpid',
                    redirect_uri => 'http://redirect.uri/',
                }
            ),
        }
    );
    expectRedirection( $res,
        qr,http://redirect.uri/.*error=invalid_request_object, );
};

subtest 'jti replay is rejected' => sub {
    my $jti     = 'jti-replay-' . time;
    my $now     = time;
    my $payload = {
        iat          => $now,
        exp          => $now + 60,
        jti          => $jti,
        client_id    => 'rpid',
        redirect_uri => 'http://redirect.uri/',
    };

    # First use: must succeed
    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'jti1',
            request       => signedRequestObject($payload),
        }
    );
    expectRedirection( $res, qr,http://redirect.uri/.*state=jti1, );

    # Second use with same jti: must be rejected
    $idpId = login( $op, 'french' );
    $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'rpid',
            scope         => 'openid',
            state         => 'jti2',
            redirect_uri  => 'http://redirect.uri/',
            request       => signedRequestObject($payload),
        }
    );
    expectRedirection( $res,
        qr,http://redirect.uri/.*error=invalid_request_object, );
};

subtest 'iat older than JarMaxAge is rejected' => sub {
    my $idpId = login( $op, 'french' );
    my $res   = authorize(
        $op, $idpId,
        {
            response_type => 'code',
            client_id     => 'maxage',
            scope         => 'openid',
            state         => 'age1',
            redirect_uri  => 'http://redirect.uri/',
            request       => $i->createJWT( {
                    iat          => time - 3600,
                    client_id    => 'maxage',
                    redirect_uri => 'http://redirect.uri/',
                },
                'HS256',
                'rpMaxAge'
            ),
        }
    );
    expectRedirection( $res,
        qr,http://redirect.uri/.*error=invalid_request_object, );
};

subtest 'Discovery advertises JAR metadata fields' => sub {
    my $res = $op->_get('/.well-known/openid-configuration');
    expectOK($res);
    my $md = expectJSON($res);

    ok(
        ref $md->{request_object_signing_alg_values_supported} eq 'ARRAY',
        'request_object_signing_alg_values_supported is an array'
    );
    ok(
        ref $md->{request_object_encryption_alg_values_supported} eq 'ARRAY',
        'request_object_encryption_alg_values_supported is an array'
    );
    ok(
        ref $md->{request_object_encryption_enc_values_supported} eq 'ARRAY',
        'request_object_encryption_enc_values_supported is an array'
    );
    ok(
        defined $md->{require_signed_request_object},
        'require_signed_request_object is advertised'
    );

    my %sigAlgs =
      map { $_ => 1 } @{ $md->{request_object_signing_alg_values_supported} };
    ok( !$sigAlgs{none},
        '"none" is never advertised as a JAR signing algorithm' );
    ok( $sigAlgs{RS256}, 'RS256 advertised for JAR signatures' );
};

clean_sessions();
done_testing();

sub op {
    return LLNG::Manager::Test->new( {
            ini => {
                logLevel                        => $debug,
                domain                          => 'idp.com',
                portal                          => 'http://auth.op.com/',
                authentication                  => 'Demo',
                userDB                          => 'Same',
                issuerDBOpenIDConnectActivation => 1,
                oidcRPMetaDataExportedVars      => {
                    rp => {
                        email       => "mail",
                        family_name => "cn",
                        name        => "cn"
                    }
                },
                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcJarRequestUriMaxSize              => 65536,
                oidcJarRequestUriTimeout              => 10,
                oidcRPMetaDataOptions                 => {
                    rp => {
                        oidcRPMetaDataOptionsDisplayName    => 'RP',
                        oidcRPMetaDataOptionsClientID       => 'rpid',
                        oidcRPMetaDataOptionsClientSecret   => 'rpid',
                        oidcRPMetaDataOptionsIDTokenSignAlg => 'RS256',
                        oidcRPMetaDataOptionsBypassConsent  => 1,
                        oidcRPMetaDataOptionsUserIDAttr     => '',
                        oidcRPMetaDataOptionsRequestUris    =>
                          'http://request.uri/*',
                        oidcRPMetaDataOptionsRedirectUris =>
                          'http://redirect.uri/',
                        oidcRPMetaDataOptionsJarSigAlg => 'HS256',
                        oidcRPMetaDataOptionsJarEncAlg => 'RSA-OAEP',
                        oidcRPMetaDataOptionsJarEncEnc => 'A128CBC-HS256',
                    },
                    strict => {
                        oidcRPMetaDataOptionsDisplayName    => 'Strict',
                        oidcRPMetaDataOptionsClientID       => 'strict',
                        oidcRPMetaDataOptionsClientSecret   => 'strictsecret',
                        oidcRPMetaDataOptionsIDTokenSignAlg => 'RS256',
                        oidcRPMetaDataOptionsBypassConsent  => 1,
                        oidcRPMetaDataOptionsUserIDAttr     => '',
                        oidcRPMetaDataOptionsRedirectUris   =>
                          'http://redirect.uri/',
                        oidcRPMetaDataOptionsRequireSignedRequestObject => 1,
                    },
                    rpMaxAge => {
                        oidcRPMetaDataOptionsDisplayName    => 'MaxAge',
                        oidcRPMetaDataOptionsClientID       => 'maxage',
                        oidcRPMetaDataOptionsClientSecret   => 'maxage',
                        oidcRPMetaDataOptionsIDTokenSignAlg => 'RS256',
                        oidcRPMetaDataOptionsBypassConsent  => 1,
                        oidcRPMetaDataOptionsUserIDAttr     => '',
                        oidcRPMetaDataOptionsRedirectUris   =>
                          'http://redirect.uri/',
                        oidcRPMetaDataOptionsJarSigAlg => 'HS256',
                        oidcRPMetaDataOptionsJarMaxAge => 60,
                    },
                },
                oidcOPMetaDataOptions           => {},
                oidcOPMetaDataJSON              => {},
                oidcOPMetaDataJWKS              => {},
                oidcServiceMetaDataAuthnContext => {
                    'loa-1' => 1,
                    'loa-2' => 2,
                    'loa-3' => 3,
                    'loa-4' => 4,
                    'loa-5' => 5,
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
                oidcServicePrivateKeyEnc => oidc_key_op_private_sig,
                oidcServicePublicKeyEnc  => oidc_cert_op_public_sig,
            },
        }
    );
}
