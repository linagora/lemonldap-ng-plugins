use warnings;
use Test::More;
use strict;
use IO::String;
use LWP::UserAgent;
use LWP::Protocol::PSGI;
use MIME::Base64 qw(encode_base64);
use JSON;
use Crypt::JWT qw(encode_jwt);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my ( $op, $res );

# JAR is loaded before PAR, as the autoloader used to do before oidc-par got
# a lower priority. The flow must still work.
$op = make_op('::Plugins::OIDCJar ::Plugins::OIDCPushedAuthRequest');
my $id = login( $op, 'french' );

subtest 'JAR loaded before PAR: a pushed request still gives a code' => sub {
    my $par_res = parRequest(
        $op, 'rpid',
        {
            response_type => 'code',
            scope         => 'openid',
            state         => 'jarfirst',
            redirect_uri  => 'http://rp.com/',
            client_id     => 'rpid',
        }
    );
    is( $par_res->[0], 201, 'PAR request returns 201 Created' );
    my $par_json = parJSON($par_res);
    like(
        $par_json->{request_uri},
        qr/^urn:ietf:params:oauth:request_uri:/,
        'request_uri has the PAR format'
    );

    my $auth_res = authorize(
        $op, $id,
        {
            client_id   => 'rpid',
            request_uri => $par_json->{request_uri},
        }
    );
    my ($code) = expectRedirection( $auth_res, qr#http://.*code=([^\&]*)# );
    ok( $code, 'authorization code received' );
};

subtest 'JAR checks apply to the request resolved by PAR' => sub {
    my $expired = signedRequestObject( {
            client_id    => 'rpid',
            redirect_uri => 'http://rp.com/',
            exp          => time - 3600,
        }
    );
    my $par_res = parRequest(
        $op, 'rpid',
        {
            response_type => 'code',
            scope         => 'openid',
            state         => 'jarexpired',
            redirect_uri  => 'http://rp.com/',
            client_id     => 'rpid',
            request       => $expired,
        }
    );
    is( $par_res->[0], 201, 'PAR request with an expired request object' );

    my $auth_res = authorize(
        $op, $id,
        {
            client_id   => 'rpid',
            request_uri => parJSON($par_res)->{request_uri},
        }
    );
    like(
        getRedirection($auth_res) // '',
        qr/error=invalid_request_object/,
        'JAR rejects the expired request object'
    );
};

subtest 'JAR requires a signed request object after PAR resolution' => sub {
    my $par_res = parRequest(
        $op, 'strict',
        {
            response_type => 'code',
            scope         => 'openid',
            state         => 'jarstrict',
            redirect_uri  => 'http://rp.com/',
            client_id     => 'strict',
        }
    );
    is( $par_res->[0], 201, 'PAR request without a request object' );

    my $auth_res = authorize(
        $op, $id,
        {
            client_id   => 'strict',
            request_uri => parJSON($par_res)->{request_uri},
        }
    );
    like(
        getRedirection($auth_res) // '',
        qr/error=request_not_supported/,
        'JAR still enforces RequireSignedRequestObject'
    );
};

clean_sessions();
done_testing();

sub signedRequestObject {
    my ($payload) = @_;
    return encode_jwt(
        payload => JSON::to_json($payload),
        alg     => 'HS256',
        key     => 'rpid',
    );
}

sub parRequest {
    local $Test::Builder::Level = $Test::Builder::Level + 1;
    my ( $op, $clientid, $params ) = @_;

    my $query = buildForm($params);
    my $res   = $op->_post(
        '/oauth2/par',
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
        custom => {
            HTTP_AUTHORIZATION => 'Basic '
              . encode_base64( "$clientid:$clientid", '' ),
        },
    );
    return $res;
}

sub parJSON {
    my $res = shift;
    return from_json( $res->[2]->[0] );
}

sub make_op {
    my ($customPlugins) = @_;
    return LLNG::Manager::Test->new( {
            ini => {
                logLevel                              => 'error',
                domain                                => 'idp.com',
                portal                                => 'http://auth.op.com/',
                authentication                        => 'Demo',
                userDB                                => 'Same',
                issuerDBOpenIDConnectActivation       => 1,
                customPlugins                         => $customPlugins,
                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcServiceMetaDataPushedAuthURI      => 'par',
                oidcServicePushedAuthExpiration       => 60,
                oidcRPMetaDataOptions                 => {
                    rp => {
                        oidcRPMetaDataOptionsDisplayName    => 'RP',
                        oidcRPMetaDataOptionsClientID       => 'rpid',
                        oidcRPMetaDataOptionsClientSecret   => 'rpid',
                        oidcRPMetaDataOptionsIDTokenSignAlg => 'RS256',
                        oidcRPMetaDataOptionsBypassConsent  => 1,
                        oidcRPMetaDataOptionsUserIDAttr     => '',
                        oidcRPMetaDataOptionsRedirectUris   => 'http://rp.com/',
                        oidcRPMetaDataOptionsPAR            => 'allowed',
                        oidcRPMetaDataOptionsJarSigAlg      => 'HS256',
                    },
                    strict => {
                        oidcRPMetaDataOptionsDisplayName    => 'Strict',
                        oidcRPMetaDataOptionsClientID       => 'strict',
                        oidcRPMetaDataOptionsClientSecret   => 'strict',
                        oidcRPMetaDataOptionsIDTokenSignAlg => 'RS256',
                        oidcRPMetaDataOptionsBypassConsent  => 1,
                        oidcRPMetaDataOptionsUserIDAttr     => '',
                        oidcRPMetaDataOptionsRedirectUris   => 'http://rp.com/',
                        oidcRPMetaDataOptionsPAR            => 'allowed',
                        oidcRPMetaDataOptionsJarSigAlg      => 'HS256',
                        oidcRPMetaDataOptionsRequireSignedRequestObject => 1,
                    },
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            },
        }
    );
}
