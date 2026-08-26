# Resource Authorization Server side of ID-JAG: consuming an assertion through
# the RFC 7523 JWT Bearer grant.
#
# The portal plays both roles here: it issues an ID-JAG for
# https://api.partner.com/ and is configured to accept assertions addressed to
# that identifier, signed by itself declared as a trusted provider.
use warnings;
use Test::More;
use strict;
use utf8;
use IO::String;
use MIME::Base64 qw/encode_base64/;
use Crypt::JWT qw(decode_jwt encode_jwt);
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my $ID_JAG     = 'urn:ietf:params:oauth:token-type:id-jag';
my $JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
my $AUDIENCE   = 'https://api.partner.com/';
my $ISSUER     = 'http://auth.op.com/';

sub conf {
    my (%extra) = @_;
    return {
        ini => {
            domain                          => 'op.com',
            portal                          => $ISSUER,
            authentication                  => 'Demo',
            userDB                          => 'Same',
            customPlugins                   =>
              '::Plugins::OIDCIdentityAssertionGrant, '
              . '::Plugins::OIDCIdentityAssertionGrantServer',
            issuerDBOpenIDConnectActivation => 1,
            oidcServiceIdJagAudience        => $AUDIENCE,
            oidcRPMetaDataExportedVars      => {
                rp  => { email => "mail", name => "cn" },
                rp2 => { email => "mail", name => "cn" },
            },
            oidcRPMetaDataOptions => {

                # Asks for the assertion, and presents it back
                rp => {
                    oidcRPMetaDataOptionsDisplayName      => "RP",
                    oidcRPMetaDataOptionsClientID         => "rpid",
                    oidcRPMetaDataOptionsClientSecret     => "rpid",
                    oidcRPMetaDataOptionsIDTokenSignAlg   => "HS512",
                    oidcRPMetaDataOptionsBypassConsent    => 1,
                    oidcRPMetaDataOptionsRefreshToken     => 1,
                    oidcRPMetaDataOptionsUserIDAttr       => "",
                    oidcRPMetaDataOptionsRedirectUris     => 'http://test/',
                    oidcRPMetaDataOptionsAllowIdJagGrant  => 1,
                    oidcRPMetaDataOptionsAllowIdJagBearer => 1,
                },

                # The resource, i.e. the audience of the assertion
                rp2 => {
                    oidcRPMetaDataOptionsDisplayName        => "RP2",
                    oidcRPMetaDataOptionsClientID           => "rpid2",
                    oidcRPMetaDataOptionsClientSecret       => "rpid2",
                    oidcRPMetaDataOptionsUserIDAttr         => "",
                    oidcRPMetaDataOptionsRedirectUris       => 'http://test/',
                    oidcRPMetaDataOptionsIdJagAudience      => $AUDIENCE,
                    oidcRPMetaDataOptionsTokenXAuthorizedRP => 'rp',
                },

                # Allowed to present an ID-JAG, but public
                rp4 => {
                    oidcRPMetaDataOptionsDisplayName       => "RP4",
                    oidcRPMetaDataOptionsClientID          => "rpid4",
                    oidcRPMetaDataOptionsPublic            => 1,
                    oidcRPMetaDataOptionsUserIDAttr        => "",
                    oidcRPMetaDataOptionsRedirectUris      => 'http://test/',
                    oidcRPMetaDataOptionsAllowIdJagBearer  => 1,
                },

                # Registered, but not allowed to present an ID-JAG
                rp3 => {
                    oidcRPMetaDataOptionsDisplayName   => "RP3",
                    oidcRPMetaDataOptionsClientID      => "rpid3",
                    oidcRPMetaDataOptionsClientSecret  => "rpid3",
                    oidcRPMetaDataOptionsUserIDAttr    => "",
                    oidcRPMetaDataOptionsRedirectUris  => 'http://test/',
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            %extra,
        }
    };
}

# 1. First portal: issue an assertion and collect our own JWKS / metadata
my $op = LLNG::Manager::Test->new( conf() );

my $jwks     = $op->_get('/oauth2/jwks')->[2]->[0];
my $metadata = $op->_get('/.well-known/openid-configuration')->[2]->[0];
ok( $jwks,     'Got our JWKS' );
ok( $metadata, 'Got our metadata' );

my $idpId = login( $op, "french" );
my $code  = codeAuthorize(
    $op, $idpId,
    {
        response_type => "code",
        scope         => "openid profile",
        client_id     => "rpid",
        state         => "af0ifjsldkj",
        redirect_uri  => "http://test/"
    }
);
my $tokens = expectJSON( codeGrant( $op, "rpid", $code, "http://test/" ) );
my $refresh_token = $tokens->{refresh_token};
ok( $refresh_token, 'Got a refresh token' );

my $assertion = expectJSON(
    tokenExchange(
        $op, 'rpid',
        requested_token_type => $ID_JAG,
        audience             => $AUDIENCE,
        subject_token        => $refresh_token,
        subject_token_type   =>
          'urn:ietf:params:oauth:token-type:refresh_token',
        scope => 'openid profile',
    )
)->{access_token};
ok( $assertion, 'Got an ID-JAG' );

# 2. Second portal: same configuration, plus ourselves as a trusted provider
my $ras = LLNG::Manager::Test->new(
    conf(
        oidcOPMetaDataJSON    => { self => $metadata },
        oidcOPMetaDataJWKS    => { self => $jwks },
        oidcOPMetaDataOptions => {
            self => {
                oidcOPMetaDataOptionsClientID          => 'unused',
                oidcOPMetaDataOptionsClientSecret      => 'unused',
                oidcOPMetaDataOptionsJWKSTimeout       => 0,
                oidcOPMetaDataOptionsAllowIdJagGrant   => 1,
            }
        },
    )
);

sub jwtBearer {
    my ( $portal, $clientid, %params ) = @_;
    my $query = buildForm( { grant_type => $JWT_BEARER, %params } );
    return $portal->_post(
        "/oauth2/token",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
        custom => {
            HTTP_AUTHORIZATION => "Basic "
              . encode_base64("$clientid:$clientid"),
        },
    );
}

sub expectError {
    my ( $res, $error, $message ) = @_;
    is( $res->[0], 400, "$message is rejected" );
    my $json = eval { JSON::from_json( $res->[2]->[0] ) };
    is( $json->{error}, $error, "$message returns $error" );
}

subtest 'metadata advertises the JWT Bearer grant' => sub {
    my $md = expectJSON(
        $ras->_get(
            '/.well-known/openid-configuration',
            accept => 'application/json'
        )
    );
    ok( ( grep { $_ eq $JWT_BEARER } @{ $md->{grant_types_supported} } ),
        'jwt-bearer is advertised' );
};

subtest 'exchange an ID-JAG for an access token' => sub {
    my $json = expectJSON( jwtBearer( $ras, 'rpid', assertion => $assertion ) );

    ok( $json->{access_token}, 'Got an access token' );
    is( $json->{token_type}, 'Bearer', 'Correct token_type' );
    ok( $json->{expires_in} > 0, 'Has a lifetime' );
    is( $json->{scope}, 'openid profile', 'Correct scope' );

    # The token is usable: userinfo resolves the asserted subject
    my $res = $ras->_post(
        '/oauth2/userinfo',
        IO::String->new(''),
        length => 0,
        accept => 'application/json',
        custom => {
            HTTP_AUTHORIZATION => "Bearer " . $json->{access_token},
        },
    );
    my $userinfo = expectJSON($res);
    is( $userinfo->{sub}, 'french', 'Access token identifies the user' );
};

subtest 'an assertion cannot be replayed' => sub {
    expectError( jwtBearer( $ras, 'rpid', assertion => $assertion ),
        'invalid_grant', 'A second use of the same assertion' );
};

subtest 'scope is bounded by the assertion' => sub {
    my $a = expectJSON(
        tokenExchange(
            $op, 'rpid',
            requested_token_type => $ID_JAG,
            audience             => $AUDIENCE,
            subject_token        => $refresh_token,
            subject_token_type   =>
              'urn:ietf:params:oauth:token-type:refresh_token',
            scope => 'openid profile',
        )
    )->{access_token};

    my $json =
      expectJSON( jwtBearer( $ras, 'rpid', assertion => $a, scope => 'openid' ) );
    is( $json->{scope}, 'openid', 'Narrower scope is honoured' );
};

subtest 'errors' => sub {
    my $fresh = sub {
        return expectJSON(
            tokenExchange(
                $op, 'rpid',
                requested_token_type => $ID_JAG,
                audience             => $AUDIENCE,
                subject_token        => $refresh_token,
                subject_token_type   =>
                  'urn:ietf:params:oauth:token-type:refresh_token',
                scope => 'openid profile',
            )
        )->{access_token};
    };

    expectError( jwtBearer( $ras, 'rpid' ),
        'invalid_request', 'A request without assertion' );

    expectError( jwtBearer( $ras, 'rpid3', assertion => $fresh->() ),
        'unauthorized_client', 'A client without the JWT Bearer grant' );

    # A plain JWT, not an ID-JAG
    my $notIdJag = encode_jwt(
        payload => { iss => $ISSUER, aud => $AUDIENCE, exp => time + 300 },
        alg     => 'RS256',
        key     => \oidc_key_op_private_sig,
    );
    expectError( jwtBearer( $ras, 'rpid', assertion => $notIdJag ),
        'invalid_grant', 'A JWT without the ID-JAG type header' );

    # Right shape, but signed by nobody we trust
    my $foreign = encode_jwt(
        payload => {
            iss       => 'https://evil.example.com/',
            sub       => 'french',
            aud       => $AUDIENCE,
            client_id => 'rpid',
            jti       => 'forged-1',
            exp       => time + 300,
        },
        alg          => 'RS256',
        key          => \oidc_key_op_private_sig,
        extra_headers => { typ => 'oauth-id-jag+jwt' },
    );
    expectError( jwtBearer( $ras, 'rpid', assertion => $foreign ),
        'invalid_grant', 'An assertion from an unknown issuer' );

    # Correct issuer, but symmetric signature
    my $symmetric = encode_jwt(
        payload => {
            iss       => $ISSUER,
            sub       => 'french',
            aud       => $AUDIENCE,
            client_id => 'rpid',
            jti       => 'forged-2',
            exp       => time + 300,
        },
        alg           => 'HS256',
        key           => 'rpid',
        extra_headers => { typ => 'oauth-id-jag+jwt' },
    );
    expectError( jwtBearer( $ras, 'rpid', assertion => $symmetric ),
        'invalid_grant', 'A symmetrically signed assertion' );

    # Addressed to another audience
    my $otherAud = expectJSON(
        tokenExchange(
            $op, 'rpid',
            requested_token_type => $ID_JAG,
            audience             => $AUDIENCE,
            subject_token        => $refresh_token,
            subject_token_type   =>
              'urn:ietf:params:oauth:token-type:refresh_token',
        )
    )->{access_token};
    my $ras2 = LLNG::Manager::Test->new(
        conf(
            oidcServiceIdJagAudience => 'https://elsewhere.example.com/',
            oidcOPMetaDataJSON       => { self => $metadata },
            oidcOPMetaDataJWKS       => { self => $jwks },
            oidcOPMetaDataOptions    => {
                self => {
                    oidcOPMetaDataOptionsClientID        => 'unused',
                    oidcOPMetaDataOptionsClientSecret    => 'unused',
                    oidcOPMetaDataOptionsJWKSTimeout     => 0,
                    oidcOPMetaDataOptionsAllowIdJagGrant => 1,
                }
            },
        )
    );
    expectError( jwtBearer( $ras2, 'rpid', assertion => $otherAud ),
        'invalid_grant', 'An assertion addressed to another server' );
};

subtest 'a public client cannot redeem an assertion' => sub {

    # An ID-JAG is a bearer credential; a public client authenticates with
    # nothing but its client_id.
    my $a = expectJSON(
        tokenExchange(
            $op, 'rpid',
            requested_token_type => $ID_JAG,
            audience             => $AUDIENCE,
            subject_token        => $refresh_token,
            subject_token_type   =>
              'urn:ietf:params:oauth:token-type:refresh_token',
        )
    )->{access_token};
    expectError( jwtBearer( $ras, 'rpid4', assertion => $a ),
        'unauthorized_client', 'A public client' );
};

subtest 'an assertion without scope grants no scope' => sub {

    # "the provider granted no scope" must not be read as "anything goes".
    my $noScope = encode_jwt(
        payload => {
            iss       => $ISSUER,
            sub       => 'french',
            aud       => $AUDIENCE,
            client_id => 'rpid',
            jti       => 'no-scope-1',
            iat       => time,
            exp       => time + 300,
        },
        alg           => 'RS256',
        key           => \oidc_key_op_private_sig,
        extra_headers => { typ => 'oauth-id-jag+jwt' },
    );
    expectError(
        jwtBearer( $ras, 'rpid', assertion => $noScope, scope => 'admin' ),
        'invalid_scope', 'A scope-less assertion' );
};

subtest 'asserted authorization_details are filtered locally' => sub {
    my $withRar = encode_jwt(
        payload => {
            iss                   => $ISSUER,
            sub                   => 'french',
            aud                   => $AUDIENCE,
            client_id             => 'rpid',
            jti                   => 'rar-1',
            iat                   => time,
            exp                   => time + 300,
            scope                 => 'openid profile',
            authorization_details =>
              [ { type => 'payment_initiation', amount => '1000000' } ],
        },
        alg           => 'RS256',
        key           => \oidc_key_op_private_sig,
        extra_headers => { typ => 'oauth-id-jag+jwt' },
    );

    # rp declares no accepted type, so nothing survives
    my $json = expectJSON( jwtBearer( $ras, 'rpid', assertion => $withRar ) );
    ok( !$json->{authorization_details},
        'Details are dropped when the local RP declares no allowlist' );
};

clean_sessions();
done_testing();
