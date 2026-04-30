use warnings;
use Test::More;
use strict;
use IO::String;
use MIME::Base64;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

# Configuration with 2 RPs: a client and a resource server (API)
my $op = LLNG::Manager::Test->new( {
        ini => {
            domain                             => 'idp.com',
            portal                             => 'http://auth.op.com/',
            authentication                     => 'Demo',
            userDB                             => 'Same',
            issuerDBOpenIDConnectActivation    => 1,
            customPlugins                      =>
              '::Plugins::OIDCResourceIndicators',
            oidcServiceAllowOnlyDeclaredScopes => 0,
            oidcServiceAllowOffline            => 1,
            oidcRPMetaDataExportedVars => {
                rp => {
                    email       => "mail",
                    family_name => "cn",
                    name        => "cn"
                },
                api => {
                    email       => "mail",
                    family_name => "cn",
                    name        => "cn"
                }
            },
            oidcRPMetaDataOptions => {

                # Normal RP
                rp => {
                    oidcRPMetaDataOptionsDisplayName    => "Client App",
                    oidcRPMetaDataOptionsClientID       => "rpid",
                    oidcRPMetaDataOptionsClientSecret   => "rpid",
                    oidcRPMetaDataOptionsAccessTokenJWT => 1,
                    oidcRPMetaDataOptionsBypassConsent  => 1,
                    oidcRPMetaDataOptionsRedirectUris   => 'http://client.com/',
                    oidcRPMetaDataOptionsIDTokenSignAlg => "HS512",
                    oidcRPMetaDataOptionsAllowOffline   => 1,
                },

                # Resource Server
                api => {
                    oidcRPMetaDataOptionsDisplayName  => "API Server",
                    oidcRPMetaDataOptionsClientID     => "api",
                    oidcRPMetaDataOptionsClientSecret => "api",
                    oidcRPMetaDataOptionsEnableRI     => 1,
                    oidcRPMetaDataOptionsRIIdentifier =>
                      "https://api.example.com",
                    oidcRPMetaDataOptionsAccessTokenJWT => 1,
                    oidcRPMetaDataOptionsBypassConsent  => 1,
                    oidcRPMetaDataOptionsRedirectUris   =>
                      'http://api.example.com/',
                    oidcRPMetaDataOptionsIDTokenSignAlg => "HS512",
                },
            },

            # RS scopes available on the API
            oidcRPMetaDataRIScopes => {
                api => {
                    'read:users'  => 'Read user data',
                    'write:users' => 'Modify user data',
                    'admin'       => 'Full admin access',
                },
            },

            # RS scope authorization rules
            oidcRPMetaDataRIScopeRules => {
                api => {
                    'read:users'  => '1',                   # Always granted
                    'write:users' => '$uid eq "french"',    # Only user 'french'
                    'admin'       => '$uid eq "admin"',     # Only user 'admin'
                },
            },

            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);

my $idpId = login( $op, "french" );

sub audience_contains {
    my ( $aud, $expected ) = @_;
    return 0 unless defined $aud;
    if ( ref($aud) eq 'ARRAY' ) {
        return grep { $_ eq $expected } @$aud;
    }
    return $aud eq $expected;
}

subtest "Token without resource param" => sub {
    my $code = codeAuthorize(
        $op, $idpId,
        {
            response_type => "code",
            scope         => "openid profile email",
            client_id     => "rpid",
            state         => "state123",
            redirect_uri  => "http://client.com/"
        }
    );

    my $json =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    my $access_token = $json->{access_token};
    ok( $access_token, 'Access token present' );

    # Decode JWT to check audience
    my $payload = id_token_payload($access_token);
    ok( audience_contains( $payload->{aud}, "rpid" ),
        "Audience contains rpid" );

    # Without resource param, there should be no RS audience
    ok(
        !audience_contains( $payload->{aud}, "https://api.example.com" ),
        "Audience does NOT contain RS identifier (no resource param)"
    );
};

subtest "Token with resource param" => sub {
    my $query = buildForm( {
            response_type => "code",
            scope         => "openid profile email read:users",
            client_id     => "rpid",
            state         => "state456",
            redirect_uri  => "http://client.com/",
            resource      => "https://api.example.com",
        }
    );

    my $res = $op->_get(
        "/oauth2/authorize",
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$idpId",
    );

    my ($code) = expectRedirection( $res, qr#http://.*code=([^\&]*)# );
    ok( $code, "Got authorization code with resource param" );

    my $json =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    my $access_token = $json->{access_token};
    ok( $access_token, 'Access token present' );

    # Decode JWT to check audience
    my $payload = id_token_payload($access_token);
    ok( audience_contains( $payload->{aud}, "rpid" ),
        "Audience contains rpid" );
    ok( audience_contains( $payload->{aud}, "https://api.example.com" ),
        "Audience contains RS identifier" );

    # Check scope via introspection
    my $intro_json = expectJSON( introspect( $op, "rpid", $access_token ) );
    ok( $intro_json->{active}, "Token is active" );
    like( $intro_json->{scope}, qr/read:users/, "Scope contains read:users" );
};

subtest "Allowed scope - always granted" => sub {
    my $query = buildForm( {
            response_type => "code",
            scope         => "openid read:users",
            client_id     => "rpid",
            state         => "state789",
            redirect_uri  => "http://client.com/",
            resource      => "https://api.example.com",
        }
    );

    my $res = $op->_get(
        "/oauth2/authorize",
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$idpId",
    );

    my ($code) = expectRedirection( $res, qr#http://.*code=([^\&]*)# );
    my $json =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    my $access_token = $json->{access_token};
    ok( $access_token, 'Access token present' );

    # Check scope via introspection
    my $intro_json = expectJSON( introspect( $op, "rpid", $access_token ) );
    ok( $intro_json->{active}, "Token is active" );
    like( $intro_json->{scope}, qr/read:users/,
        "read:users scope is granted (rule='1')" );
};

subtest "Scope with user rule - granted" => sub {
    my $query = buildForm( {
            response_type => "code",
            scope         => "openid write:users",
            client_id     => "rpid",
            state         => "stateABC",
            redirect_uri  => "http://client.com/",
            resource      => "https://api.example.com",
        }
    );

    my $res = $op->_get(
        "/oauth2/authorize",
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$idpId",
    );

    my ($code) = expectRedirection( $res, qr#http://.*code=([^\&]*)# );
    my $json =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    my $access_token = $json->{access_token};
    ok( $access_token, 'Access token present' );

    # Check scope via introspection
    my $intro_json = expectJSON( introspect( $op, "rpid", $access_token ) );
    ok( $intro_json->{active}, "Token is active" );
    like( $intro_json->{scope}, qr/write:users/,
        "write:users scope is granted for user 'french'" );
};

subtest "Denied scope - user not matching rule" => sub {
    my $query = buildForm( {
            response_type => "code",
            scope         => "openid admin",
            client_id     => "rpid",
            state         => "stateDEF",
            redirect_uri  => "http://client.com/",
            resource      => "https://api.example.com",
        }
    );

    my $res = $op->_get(
        "/oauth2/authorize",
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$idpId",
    );

    my ($code) = expectRedirection( $res, qr#http://.*code=([^\&]*)# );
    my $json =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    my $access_token = $json->{access_token};
    ok( $access_token, 'Access token present' );

    # Check scope via introspection - admin should NOT be present
    my $intro_json = expectJSON( introspect( $op, "rpid", $access_token ) );
    ok( $intro_json->{active}, "Token is active" );
    my $scope = $intro_json->{scope} // '';
    unlike( $scope, qr/\badmin\b/,
        "admin scope is NOT granted for user 'french'" );
};

subtest "Unknown audience ignored" => sub {
    my $query = buildForm( {
            response_type => "code",
            scope         => "openid profile",
            client_id     => "rpid",
            state         => "stateGHI",
            redirect_uri  => "http://client.com/",
            resource      => "https://unknown.api.com",
        }
    );

    my $res = $op->_get(
        "/oauth2/authorize",
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$idpId",
    );

    # Should still work, just ignore the unknown audience
    my ($code) = expectRedirection( $res, qr#http://.*code=([^\&]*)# );
    ok( $code, "Got authorization code (unknown audience ignored)" );

    my $json =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    my $access_token = $json->{access_token};
    ok( $access_token, 'Access token present' );

    # Audience should only contain rpid (unknown RS is ignored)
    my $payload = id_token_payload($access_token);
    ok( audience_contains( $payload->{aud}, "rpid" ),
        "Audience contains rpid" );
    ok( !audience_contains( $payload->{aud}, "https://unknown.api.com" ),
        "Unknown audience is not in token" );
};

subtest "Multiple RS scopes - some granted, some denied" => sub {
    my $query = buildForm( {
            response_type => "code",
            scope         => "openid read:users write:users admin",
            client_id     => "rpid",
            state         => "stateJKL",
            redirect_uri  => "http://client.com/",
            resource      => "https://api.example.com",
        }
    );

    my $res = $op->_get(
        "/oauth2/authorize",
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$idpId",
    );

    my ($code) = expectRedirection( $res, qr#http://.*code=([^\&]*)# );
    my $json =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    my $access_token = $json->{access_token};
    ok( $access_token, 'Access token present' );

    # Check scopes via introspection
    my $intro_json = expectJSON( introspect( $op, "rpid", $access_token ) );
    ok( $intro_json->{active}, "Token is active" );
    my $scope = $intro_json->{scope} // '';

    like( $scope, qr/read:users/,  "read:users granted" );
    like( $scope, qr/write:users/, "write:users granted (french)" );
    unlike( $scope, qr/\badmin\b/, "admin denied (not admin user)" );
};

subtest "Token introspection" => sub {
    my $query = buildForm( {
            response_type => "code",
            scope         => "openid read:users",
            client_id     => "rpid",
            state         => "stateMNO",
            redirect_uri  => "http://client.com/",
            resource      => "https://api.example.com",
        }
    );

    my $res = $op->_get(
        "/oauth2/authorize",
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$idpId",
    );

    my ($code) = expectRedirection( $res, qr#http://.*code=([^\&]*)# );
    my $json =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    my $access_token = $json->{access_token};
    ok( $access_token, 'Access token present' );

    # Introspect the token
    my $intro_json = expectJSON( introspect( $op, "rpid", $access_token ) );

    ok( $intro_json->{active}, "Token is active" );
    like( $intro_json->{scope}, qr/read:users/,
        "Introspection shows RS scope" );

    # Verify introspection includes RS audience (RFC 8707)
    ok(
        audience_contains( $intro_json->{aud}, "rpid" ),
        "Introspection aud contains client_id"
    );
    ok( audience_contains( $intro_json->{aud}, "https://api.example.com" ),
        "Introspection aud contains RS identifier" );
};

subtest "Userinfo with RS token" => sub {
    my $query = buildForm( {
            response_type => "code",
            scope         => "openid profile email read:users",
            client_id     => "rpid",
            state         => "statePQR",
            redirect_uri  => "http://client.com/",
            resource      => "https://api.example.com",
        }
    );

    my $res = $op->_get(
        "/oauth2/authorize",
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$idpId",
    );

    my ($code) = expectRedirection( $res, qr#http://.*code=([^\&]*)# );
    my $json =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    my $access_token = $json->{access_token};
    ok( $access_token, 'Access token present' );

    # Call userinfo endpoint
    $res = $op->_get(
        "/oauth2/userinfo",
        accept => 'application/json',
        custom => { HTTP_AUTHORIZATION => "Bearer $access_token" },
    );
    expectOK($res);
    my $userinfo = expectJSON($res);

    # Userinfo should return OIDC claims (profile, email), not aud
    ok( $userinfo->{sub},   "Userinfo has sub" );
    ok( $userinfo->{email}, "Userinfo has email (from email scope)" );
    ok( $userinfo->{name},  "Userinfo has name (from profile scope)" );

    # Userinfo should NOT contain aud (only in tokens)
    ok( !exists $userinfo->{aud}, "Userinfo does NOT contain aud" );
};

subtest "Multiple resource parameters (RFC 8707 multi-value)" => sub {

    # The test sends two `resource` values (one known, one unknown) and
    # verifies the plugin reads BOTH of them via Plack::Request list-context
    # `param`. The unknown audience must be silently ignored (already
    # covered by another subtest); the known one must surface in aud.
    # Sending the resource param twice also exercises the dedup path —
    # had the plugin used scalar-context `$req->param('resource')`, only
    # the first occurrence would have been seen.
    my $query = "response_type=code"
      . "&scope=openid+read%3Ausers"
      . "&client_id=rpid"
      . "&state=multires"
      . "&redirect_uri=http%3A%2F%2Fclient.com%2F"
      . "&resource=https%3A%2F%2Fapi.example.com"
      . "&resource=https%3A%2F%2Funknown.example.org";

    my $res = $op->_get(
        "/oauth2/authorize",
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$idpId",
    );
    my ($code) = expectRedirection( $res, qr#http://.*code=([^\&]*)# );
    ok( $code, "Got code with two `resource` params" );

    my $json =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    my $payload = id_token_payload( $json->{access_token} );
    ok( audience_contains( $payload->{aud}, "https://api.example.com" ),
        "Known resource surfaces in aud (proves multi-value reading)" );
    ok( !audience_contains( $payload->{aud}, "https://unknown.example.org" ),
        "Unknown resource is ignored, not echoed in aud" );
};

subtest "Refresh token preserves RS audience" => sub {
    my $query = buildForm( {
            response_type => "code",
            scope         => "openid profile read:users offline_access",
            client_id     => "rpid",
            state         => "refresh-test",
            redirect_uri  => "http://client.com/",
            resource      => "https://api.example.com",
        }
    );
    my $res = $op->_get(
        "/oauth2/authorize",
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$idpId",
    );
    my ($code) = expectRedirection( $res, qr#http://.*code=([^\&]*)# );
    my $token_res =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    ok( $token_res->{refresh_token}, "Refresh token issued" );

    my $rt_query = buildForm( {
            grant_type    => "refresh_token",
            refresh_token => $token_res->{refresh_token},
    } );
    my $refresh_res = $op->_post(
        "/oauth2/token",
        IO::String->new($rt_query),
        accept => 'application/json',
        length => length($rt_query),
        custom => {
            HTTP_AUTHORIZATION => "Basic "
              . encode_base64( "rpid:rpid", '' ),
        },
    );
    my $refresh_json = expectJSON($refresh_res);
    ok( $refresh_json->{access_token},
        "New access token issued from refresh" );

    my $payload = id_token_payload( $refresh_json->{access_token} );
    ok( audience_contains( $payload->{aud}, "https://api.example.com" ),
        "Refresh-issued AT still has the RS audience" );
};

clean_sessions();
done_testing();
