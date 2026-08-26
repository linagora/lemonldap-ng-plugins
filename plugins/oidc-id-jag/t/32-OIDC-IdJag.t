use warnings;
use Test::More;
use strict;
use utf8;
use IO::String;
use MIME::Base64;
use Crypt::JWT qw(decode_jwt encode_jwt);
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my $ID_JAG   = 'urn:ietf:params:oauth:token-type:id-jag';
my $AUDIENCE = 'https://api.partner.com/';

my $baseConfig = {
    ini => {
        domain                          => 'op.com',
        portal                          => 'http://auth.op.com/',
        authentication                  => 'Demo',
        userDB                          => 'Same',
        customPlugins                   =>
          '::Plugins::OIDCIdentityAssertionGrant',
        issuerDBOpenIDConnectActivation => 1,
        oidcRPMetaDataExportedVars      => {
            rp => {
                email       => "mail",
                family_name => "cn",
                name        => "cn",
            },
            rp2 => {
                email       => "mail",
                family_name => "cn",
                name        => "cn",
            },
            rp5 => {
                email       => "mail",
                family_name => "cn",
                name        => "cn",
            },
        },
        oidcRPMetaDataOptions => {

            # The client asking for an ID-JAG
            rp => {
                oidcRPMetaDataOptionsDisplayName     => "RP",
                oidcRPMetaDataOptionsClientID        => "rpid",
                oidcRPMetaDataOptionsClientSecret    => "rpid",
                oidcRPMetaDataOptionsIDTokenSignAlg  => "RS256",
                oidcRPMetaDataOptionsBypassConsent   => 1,
                oidcRPMetaDataOptionsRefreshToken    => 1,
                oidcRPMetaDataOptionsUserIDAttr      => "",
                oidcRPMetaDataOptionsRedirectUris    => 'http://test/',
                oidcRPMetaDataOptionsAllowIdJagGrant => 1,
            },

            # The Resource Authorization Server
            rp2 => {
                oidcRPMetaDataOptionsDisplayName        => "RP2",
                oidcRPMetaDataOptionsClientID           => "rpid2",
                oidcRPMetaDataOptionsClientSecret       => "rpid2",
                oidcRPMetaDataOptionsIDTokenSignAlg     => "HS512",
                oidcRPMetaDataOptionsUserIDAttr         => "",
                oidcRPMetaDataOptionsRedirectUris       => 'http://test/',
                oidcRPMetaDataOptionsIdJagAudience      => $AUDIENCE,
                oidcRPMetaDataOptionsTokenXAuthorizedRP => 'rp rp4 rp5',
            },

            # Another Resource Authorization Server, rp is not allowed on it.
            # Its client is not allowed to request an ID-JAG either.
            rp3 => {
                oidcRPMetaDataOptionsDisplayName   => "RP3",
                oidcRPMetaDataOptionsClientID      => "rpid3",
                oidcRPMetaDataOptionsClientSecret  => "rpid3",
                oidcRPMetaDataOptionsUserIDAttr    => "",
                oidcRPMetaDataOptionsRedirectUris  => 'http://test/',
                oidcRPMetaDataOptionsIdJagAudience => 'https://api.other.com/',
            },

            # Allowed to ask for an ID-JAG, and *not* allowed to get refresh
            # tokens: its ID tokens can only be resolved through the sid index
            rp5 => {
                oidcRPMetaDataOptionsDisplayName      => "RP5",
                oidcRPMetaDataOptionsClientID         => "rpid5",
                oidcRPMetaDataOptionsClientSecret     => "rpid5",
                oidcRPMetaDataOptionsIDTokenSignAlg   => "RS256",
                oidcRPMetaDataOptionsBypassConsent    => 1,
                oidcRPMetaDataOptionsUserIDAttr       => "",
                oidcRPMetaDataOptionsRedirectUris     => 'http://test/',
                oidcRPMetaDataOptionsAllowIdJagGrant  => 1,
            },

            # Allowed to ask for an ID-JAG, but owns no token
            rp4 => {
                oidcRPMetaDataOptionsDisplayName     => "RP4",
                oidcRPMetaDataOptionsClientID        => "rpid4",
                oidcRPMetaDataOptionsClientSecret    => "rpid4",
                oidcRPMetaDataOptionsUserIDAttr      => "",
                oidcRPMetaDataOptionsRedirectUris    => 'http://test/',
                oidcRPMetaDataOptionsAllowIdJagGrant => 1,
            },
        },
        oidcServicePrivateKeySig => oidc_key_op_private_sig,
        oidcServicePublicKeySig  => oidc_cert_op_public_sig,
    }
};

my $op = LLNG::Manager::Test->new($baseConfig);

# Advertised in metadata
subtest 'metadata' => sub {
    my $res = $op->_get( '/.well-known/openid-configuration',
        accept => 'application/json' );
    my $metadata = expectJSON($res);
    ok( (
            grep { $_ eq 'urn:ietf:params:oauth:grant-type:token-exchange' }
              @{ $metadata->{grant_types_supported} }
        ),
        'Token exchange is advertised'
    );
    is_deeply( $metadata->{identity_chaining_requested_token_types_supported},
        [$ID_JAG], 'ID-JAG is advertised' );
};

# Get tokens for "rp"
my $idpId = login( $op, "french" );
my $code  = codeAuthorize(
    $op, $idpId,
    {
        response_type => "code",
        scope         => "openid profile email",
        client_id     => "rpid",
        state         => "af0ifjsldkj",
        redirect_uri  => "http://test/"
    }
);
my $json = expectJSON( codeGrant( $op, "rpid", $code, "http://test/" ) );
my $access_token  = $json->{access_token};
my $refresh_token = $json->{refresh_token};
my $id_token      = $json->{id_token};
ok( $access_token,  'Got access token' );
ok( $refresh_token, 'Got refresh token' );
ok( $id_token,      'Got ID token' );

sub getIdJag {
    my (%params) = @_;
    return tokenExchange(
        $op,
        delete $params{_client} || 'rpid',
        requested_token_type => $ID_JAG,
        audience             => $AUDIENCE,
        subject_token        => $refresh_token,
        subject_token_type   =>
          'urn:ietf:params:oauth:token-type:refresh_token',
        %params,
    );
}

subtest 'ID-JAG from a refresh token' => sub {
    my $res  = getIdJag( scope => 'openid profile' );
    my $json = expectJSON($res);

    is( $json->{issued_token_type}, $ID_JAG, 'Correct issued_token_type' );
    is( $json->{token_type},        'N_A',   'Correct token_type' );
    is( $json->{expires_in},        300,     'Default lifetime' );
    is( $json->{scope},             'openid profile', 'Scope was returned' );

    my $assertion = $json->{access_token};
    ok( $assertion, 'Got an assertion' );

    my $header = getJWTHeader($assertion);
    is( $header->{typ}, 'oauth-id-jag+jwt', 'Correct JWT type' );
    is( $header->{alg}, 'RS256',            'Correct signature algorithm' );

    # Signature must verify against the published key of the OP
    my $payload =
      eval { decode_jwt( token => $assertion, key => \oidc_key_op_public_sig ) };
    ok( $payload, "Assertion signature is valid" ) or diag $@;

    is( $payload->{iss},       'http://auth.op.com/', 'Correct issuer' );
    is( $payload->{aud},       $AUDIENCE,             'Correct audience' );
    is( $payload->{sub},       'french',              'Correct subject' );
    is( $payload->{client_id}, 'rpid',                'Correct client_id' );
    is( $payload->{scope},     'openid profile',      'Correct scope' );
    ok( $payload->{jti}, 'Assertion has a jti' );
    cmp_ok( $payload->{exp}, '>',  time,       'Assertion is not expired' );
    cmp_ok( $payload->{exp}, '<=', time + 300, 'Assertion is short lived' );
};

subtest 'ID-JAG from an access token' => sub {
    my $res = getIdJag(
        subject_token      => $access_token,
        subject_token_type => 'urn:ietf:params:oauth:token-type:access_token',
    );
    my $json    = expectJSON($res);
    my $payload = eval {
        decode_jwt(
            token => $json->{access_token},
            key   => \oidc_key_op_public_sig
        );
    };
    is( $payload->{sub}, 'french', 'Correct subject' );
};

subtest 'ID-JAG from an ID token' => sub {
    my $res = getIdJag(
        subject_token      => $id_token,
        subject_token_type => 'urn:ietf:params:oauth:token-type:id_token',
    );
    my $json    = expectJSON($res);
    my $payload = eval {
        decode_jwt(
            token => $json->{access_token},
            key   => \oidc_key_op_public_sig
        );
    };
    is( $payload->{sub},       'french', 'Correct subject' );
    is( $payload->{client_id}, 'rpid',   'Correct client_id' );
};

subtest 'ID token with an asymmetric signature' => sub {
    $baseConfig->{ini}->{oidcRPMetaDataOptions}->{rp}
      ->{oidcRPMetaDataOptionsIDTokenSignAlg} = 'RS512';
    my $op2 = LLNG::Manager::Test->new($baseConfig);
    my $id  = login( $op2, "french" );
    my $c   = codeAuthorize(
        $op2, $id,
        {
            response_type => "code",
            scope         => "openid profile email",
            client_id     => "rpid",
            state         => "af0ifjsldkj",
            redirect_uri  => "http://test/"
        }
    );
    my $tokens = expectJSON( codeGrant( $op2, "rpid", $c, "http://test/" ) );

    my $saved = $op;
    $op = $op2;
    my $json = expectJSON(
        getIdJag(
            subject_token      => $tokens->{id_token},
            subject_token_type => 'urn:ietf:params:oauth:token-type:id_token',
        )
    );
    my $payload = eval {
        decode_jwt(
            token => $json->{access_token},
            key   => \oidc_key_op_public_sig
        );
    };
    is( $payload->{sub}, 'french', 'Correct subject' );
    $op = $saved;
    $baseConfig->{ini}->{oidcRPMetaDataOptions}->{rp}
      ->{oidcRPMetaDataOptionsIDTokenSignAlg} = 'RS256';
};

subtest 'client_id override' => sub {
    $baseConfig->{ini}->{oidcRPMetaDataOptions}->{rp}
      ->{oidcRPMetaDataOptionsIdJagClientId} = 'remote-client';
    my $op2   = LLNG::Manager::Test->new($baseConfig);
    my $saved = $op;
    $op = $op2;
    my $json    = expectJSON( getIdJag() );
    my $payload = decode_jwt(
        token => $json->{access_token},
        key   => \oidc_key_op_public_sig
    );
    is( $payload->{client_id}, 'remote-client', 'client_id was overridden' );
    delete $baseConfig->{ini}->{oidcRPMetaDataOptions}->{rp}
      ->{oidcRPMetaDataOptionsIdJagClientId};
    $op = $saved;
};

subtest 'ID token of a client without refresh tokens' => sub {

    # rp5 cannot get a refresh token, so no session carries the `sid` of its
    # ID tokens: resolution goes through the index maintained by the plugin.
    my $c = codeAuthorize(
        $op, $idpId,
        {
            response_type => "code",
            scope         => "openid profile",
            client_id     => "rpid5",
            state         => "af0ifjsldkj",
            redirect_uri  => "http://test/"
        }
    );
    my $tokens = expectJSON( codeGrant( $op, "rpid5", $c, "http://test/" ) );
    ok( $tokens->{id_token}, 'Got an ID token' );
    ok( !$tokens->{refresh_token}, 'And no refresh token' );

    my $json = expectJSON(
        getIdJag(
            _client            => 'rpid5',
            subject_token      => $tokens->{id_token},
            subject_token_type => 'urn:ietf:params:oauth:token-type:id_token',
        )
    );
    my $payload = eval {
        decode_jwt(
            token => $json->{access_token},
            key   => \oidc_key_op_public_sig
        );
    };
    ok( $payload, 'Got an assertion' ) or diag $@;
    is( $payload->{sub},       'french', 'Correct subject' );
    is( $payload->{client_id}, 'rpid5',  'Correct client_id' );
};

subtest 'repeated `resource` cannot inject claims' => sub {

    # $req->param() is list-context aware. Interpolated straight into the
    # payload hash literal it let a client repeat the parameter and overwrite
    # any claim set before it -- `sub` included.
    my $query = buildForm( {
            grant_type           =>
              'urn:ietf:params:oauth:grant-type:token-exchange',
            requested_token_type => $ID_JAG,
            audience             => $AUDIENCE,
            subject_token        => $refresh_token,
            subject_token_type   =>
              'urn:ietf:params:oauth:token-type:refresh_token',
        }
    );
    $query .= '&resource=https%3A%2F%2Fx'
      . '&resource=sub&resource=victim%40evil.example'
      . '&resource=exp&resource=9999999999';

    my $res = $op->_post(
        "/oauth2/token",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
        custom =>
          { HTTP_AUTHORIZATION => "Basic " . encode_base64("rpid:rpid") },
    );
    is( $res->[0], 400, 'Several resource parameters are rejected' );
    is( eval { JSON::from_json( $res->[2]->[0] ) }->{error},
        'invalid_request', 'Ambiguous resource returns invalid_request' );

    # And a single one still lands as a plain scalar claim
    my $payload = decode_jwt(
        token => expectJSON( getIdJag( resource => 'https://x' ) )->{access_token},
        key   => \oidc_key_op_public_sig
    );
    is( $payload->{sub},      'french',     'sub claim is intact' );
    is( $payload->{resource}, 'https://x',  'resource is a single scalar' );
    cmp_ok( $payload->{exp}, '<=', time + 300, 'exp is not attacker-controlled' );
};

subtest 'scope is bounded by the subject token' => sub {

    # The refresh token was granted "openid profile email"; asking for more
    # must not widen the assertion.
    my $json = expectJSON( getIdJag( scope => 'openid profile admin' ) );
    my %got  = map { $_ => 1 } split /\s+/, ( $json->{scope} || '' );
    ok( !$got{admin}, 'An unrelated scope is not granted' );
    ok( $got{openid}, 'Legitimate scopes survive' );
};

subtest 'an expired ID token is refused' => sub {
    my $expired = encode_jwt(
        payload => {
            iss => 'http://auth.op.com/',
            aud => 'rpid',
            azp => 'rpid',
            sub => 'french',
            sid => 'whatever',
            exp => time - 3600,
        },
        alg => 'RS256',
        key => \oidc_key_op_private_sig,
    );
    expectError(
        getIdJag(
            subject_token      => $expired,
            subject_token_type => 'urn:ietf:params:oauth:token-type:id_token',
        ),
        'invalid_grant',
        'An expired ID token'
    );
};

subtest 'an HS-signed ID token is refused as subject_token' => sub {

    # The client knows the secret those are signed with, so it could mint one
    # with any sid and pivot to another user's session.
    $baseConfig->{ini}->{oidcRPMetaDataOptions}->{rp}
      ->{oidcRPMetaDataOptionsIDTokenSignAlg} = 'HS512';
    my $op2 = LLNG::Manager::Test->new($baseConfig);
    my $id  = login( $op2, "french" );
    my $c   = codeAuthorize(
        $op2, $id,
        {
            response_type => "code",
            scope         => "openid profile",
            client_id     => "rpid",
            state         => "af0ifjsldkj",
            redirect_uri  => "http://test/"
        }
    );
    my $tokens = expectJSON( codeGrant( $op2, "rpid", $c, "http://test/" ) );

    my $saved = $op;
    $op = $op2;
    expectError(
        getIdJag(
            subject_token      => $tokens->{id_token},
            subject_token_type => 'urn:ietf:params:oauth:token-type:id_token',
        ),
        'invalid_grant',
        'A client-forgeable HS512 ID token'
    );
    $op = $saved;
    $baseConfig->{ini}->{oidcRPMetaDataOptions}->{rp}
      ->{oidcRPMetaDataOptionsIDTokenSignAlg} = 'RS256';
};

sub expectError {
    my ( $res, $error, $message ) = @_;
    is( $res->[0], 400, "$message is rejected" );
    my $json = eval { JSON::from_json( $res->[2]->[0] ) };
    is( $json->{error}, $error, "$message returns $error" );
}

subtest 'errors' => sub {
    expectError( getIdJag( audience => 'https://unknown.example.com/' ),
        'invalid_target', 'Unknown audience' );

    expectError( getIdJag( audience => 'https://api.other.com/' ),
        'access_denied', 'Unauthorized audience' );

    expectError(
        getIdJag( _client => 'rpid3' ),
        'unauthorized_client',
        'Client without ID-JAG grant'
    );

    expectError( getIdJag( audience => undef ),
        'invalid_request', 'Missing audience' );

    expectError( getIdJag( subject_token => 'nonexistent' ),
        'invalid_grant', 'Unknown subject_token' );

    # A token issued to another client cannot be exchanged
    expectError( getIdJag( _client => 'rpid4' ),
        'invalid_grant', 'subject_token of another client' );

    # A well signed ID token with an unknown sid resolves to nothing
    my $forged = encode_jwt(
        payload => {
            iss => 'http://auth.op.com/',
            azp => 'rpid',
            sub => 'french',
            sid => 'unknown-sid',
            exp => time + 300,
        },
        alg => 'HS512',
        key => 'rpid',
    );
    expectError(
        getIdJag(
            subject_token      => $forged,
            subject_token_type => 'urn:ietf:params:oauth:token-type:id_token',
        ),
        'invalid_grant',
        'ID token with an unknown sid'
    );

    # An ID token signed with the wrong secret is refused
    my $badlySigned = encode_jwt(
        payload => {
            iss => 'http://auth.op.com/',
            azp => 'rpid',
            sid => 'whatever',
            exp => time + 300,
        },
        alg => 'HS512',
        key => 'not-the-secret',
    );
    expectError(
        getIdJag(
            subject_token      => $badlySigned,
            subject_token_type => 'urn:ietf:params:oauth:token-type:id_token',
        ),
        'invalid_grant',
        'Badly signed ID token'
    );
};

clean_sessions();
done_testing();
