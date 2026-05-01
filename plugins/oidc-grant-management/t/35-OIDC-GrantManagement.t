use warnings;
use Test::More;
use strict;
use IO::String;
use MIME::Base64 qw/encode_base64 decode_base64/;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

ok( my $op = register( 'op', sub { op() } ), 'OP portal' );
my $idpId = login( $op, "french" );

sub jwt_payload {
    my $jwt = shift;
    my ( undef, $body ) = split /\./, $jwt;
    $body =~ tr{-_}{+/};
    $body .= '=' x ( ( 4 - length($body) % 4 ) % 4 );
    return decode_json( decode_base64($body) );
}

sub gm_get {
    my ( $op, $client_id, $grant_id ) = @_;
    return $op->_get(
        "/oauth2/grants/$grant_id",
        accept => 'application/json',
        custom => {
            HTTP_AUTHORIZATION => "Basic "
              . encode_base64( "$client_id:$client_id", '' ),
        },
    );
}

sub gm_delete {
    my ( $op, $client_id, $grant_id ) = @_;
    return $op->_get(
        "/oauth2/grants/$grant_id",
        accept => 'application/json',
        custom => {
            REQUEST_METHOD     => 'DELETE',
            HTTP_AUTHORIZATION => "Basic "
              . encode_base64( "$client_id:$client_id", '' ),
        },
    );
}

subtest "Discovery advertises grant_management endpoint and actions" => sub {
    my $res = $op->_get(
        "/.well-known/openid-configuration",
        accept => 'application/json',
    );
    my $json = expectJSON($res);
    ok( $json->{grant_management_endpoint},
        "grant_management_endpoint present" );
    like(
        $json->{grant_management_endpoint},
        qr{/oauth2/grants$},
        "endpoint URL ends with /oauth2/grants"
    );
    is_deeply(
        [ sort @{ $json->{grant_management_actions_supported} || [] } ],
        [qw(create replace update)],
        "supported actions are create/replace/update"
    );
};

subtest "Default authorize (no action) does not emit grant_id" => sub {
    my $code = codeAuthorize(
        $op, $idpId,
        {
            response_type => "code",
            scope         => "openid profile",
            client_id     => "rpid",
            state         => "noaction",
            redirect_uri  => "http://client.com/",
        }
    );
    my $token_res =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    ok( !defined $token_res->{grant_id},
        "no grant_id without grant_management_action" );
};

my $created_grant_id;

subtest "action=create emits a fresh grant_id, claim and introspection" => sub {
    my $code = codeAuthorize(
        $op, $idpId,
        {
            response_type            => "code",
            scope                    => "openid profile read",
            client_id                => "rpid",
            state                    => "create",
            redirect_uri             => "http://client.com/",
            grant_management_action  => "create",
        }
    );
    my $token_res =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    ok( $token_res->{grant_id}, "grant_id present in token response" );
    $created_grant_id = $token_res->{grant_id};

    my $payload = jwt_payload( $token_res->{access_token} );
    is( $payload->{grant_id}, $created_grant_id,
        "JWT access token carries grant_id claim" );

    my $intro = expectJSON( introspect( $op, "rpid",
            $token_res->{access_token} ) );
    is( $intro->{grant_id}, $created_grant_id,
        "Introspection response carries grant_id" );
};

subtest "GET /oauth2/grants/{id} returns the grant content" => sub {
    my $res = gm_get( $op, "rpid", $created_grant_id );
    is( $res->[0], 200, "Returns 200 OK" );
    my $json = expectJSON($res);
    my @scope_names = map { $_->{scope} } @{ $json->{scopes} || [] };
    is_deeply(
        [ sort @scope_names ],
        [qw(openid profile read)],
        "Grant carries the granted scopes"
    );
};

subtest "action=update merges the new scope into the existing grant" => sub {
    my $code = codeAuthorize(
        $op, $idpId,
        {
            response_type           => "code",
            scope                   => "openid profile write",
            client_id               => "rpid",
            state                   => "update",
            redirect_uri            => "http://client.com/",
            grant_management_action => "update",
            grant_id                => $created_grant_id,
        }
    );
    my $token_res =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    is( $token_res->{grant_id}, $created_grant_id,
        "Same grant_id returned after update" );

    my $res = gm_get( $op, "rpid", $created_grant_id );
    my $json = expectJSON($res);
    my @scope_names = map { $_->{scope} } @{ $json->{scopes} || [] };
    is_deeply(
        [ sort @scope_names ],
        [qw(openid profile read write)],
        "Grant scope set is the union (read kept, write added)"
    );
};

subtest "action=replace replaces the scope set entirely" => sub {
    my $code = codeAuthorize(
        $op, $idpId,
        {
            response_type           => "code",
            scope                   => "openid admin",
            client_id               => "rpid",
            state                   => "replace",
            redirect_uri            => "http://client.com/",
            grant_management_action => "replace",
            grant_id                => $created_grant_id,
        }
    );
    my $token_res =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    is( $token_res->{grant_id}, $created_grant_id,
        "Same grant_id returned after replace" );

    my $res = gm_get( $op, "rpid", $created_grant_id );
    my $json = expectJSON($res);
    my @scope_names = map { $_->{scope} } @{ $json->{scopes} || [] };
    is_deeply(
        [ sort @scope_names ],
        [qw(admin openid)],
        "Grant scope set is just the new scopes (read/write/profile gone)"
    );
};

subtest "DELETE /oauth2/grants/{id} returns 204 and the grant is gone" => sub {
    my $res = gm_delete( $op, "rpid", $created_grant_id );
    is( $res->[0], 204, "Returns 204 No Content" );

    my $get_after = gm_get( $op, "rpid", $created_grant_id );
    is( $get_after->[0], 404, "GET on deleted grant returns 404" );
    my $json = from_json( $get_after->[2]->[0] );
    is( $json->{error}, "invalid_grant", "error code is invalid_grant" );
};

subtest "Cannot access another client's grant" => sub {

    # Create a grant for rpid
    my $code = codeAuthorize(
        $op, $idpId,
        {
            response_type           => "code",
            scope                   => "openid",
            client_id               => "rpid",
            state                   => "owner",
            redirect_uri            => "http://client.com/",
            grant_management_action => "create",
        }
    );
    my $token_res =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    my $someone_grant = $token_res->{grant_id};

    # Try to GET it as a different client
    my $res = gm_get( $op, "rpid_other", $someone_grant );
    is( $res->[0], 403,
        "Returns 403 Forbidden when client doesn't own the grant" );
};

subtest "RP with mode=required rejects authorize without action" => sub {
    my $auth_res = authorize(
        $op, $idpId,
        {
            response_type => "code",
            scope         => "openid",
            client_id     => "rpid_strict",
            state         => "strict",
            redirect_uri  => "http://client.com/",
        }
    );
    expectPortalError( $auth_res, 24,
        "Authorize without grant_management_action is rejected" );
};

subtest "Unknown action is rejected" => sub {
    my $auth_res = authorize(
        $op, $idpId,
        {
            response_type           => "code",
            scope                   => "openid",
            client_id               => "rpid",
            state                   => "bad",
            redirect_uri            => "http://client.com/",
            grant_management_action => "merge",   # not in v1 supported set
        }
    );
    expectPortalError( $auth_res, 24, "Unknown action is rejected" );
};

subtest "update without grant_id is rejected" => sub {
    my $auth_res = authorize(
        $op, $idpId,
        {
            response_type           => "code",
            scope                   => "openid",
            client_id               => "rpid",
            state                   => "missingid",
            redirect_uri            => "http://client.com/",
            grant_management_action => "update",
        }
    );
    expectPortalError( $auth_res, 24,
        "update without grant_id is rejected" );
};

clean_sessions();
done_testing();

sub op {
    return LLNG::Manager::Test->new( {
            ini => {
                domain                          => 'idp.com',
                portal                          => 'http://auth.op.com/',
                authentication                  => 'Demo',
                userDB                          => 'Same',
                customPlugins                   =>
                  '::Plugins::OIDCGrantManagement',
                issuerDBOpenIDConnectActivation => "1",
                restSessionServer               => 1,

                oidcServiceMetaDataGrantManagementURI => 'grants',
                oidcServiceGrantExpiration            => 3600,

                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcServiceAllowOnlyDeclaredScopes    => 0,

                oidcRPMetaDataExportedVars => {
                    rp           => { email => "mail", name => "cn" },
                    rp_other     => { email => "mail", name => "cn" },
                    rp_strict    => { email => "mail", name => "cn" },
                },
                oidcRPMetaDataOptions => {
                    rp => {
                        oidcRPMetaDataOptionsDisplayName           => "RP",
                        oidcRPMetaDataOptionsClientID              => "rpid",
                        oidcRPMetaDataOptionsClientSecret          => "rpid",
                        oidcRPMetaDataOptionsIDTokenSignAlg        => "HS512",
                        oidcRPMetaDataOptionsAccessTokenJWT        => 1,
                        oidcRPMetaDataOptionsAccessTokenSignAlg    => "HS512",
                        oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                        oidcRPMetaDataOptionsBypassConsent         => 1,
                        oidcRPMetaDataOptionsRedirectUris   => 'http://client.com/',
                        oidcRPMetaDataOptionsGrantManagement => 'allowed',
                    },
                    rp_other => {
                        oidcRPMetaDataOptionsDisplayName           => "Other RP",
                        oidcRPMetaDataOptionsClientID              => "rpid_other",
                        oidcRPMetaDataOptionsClientSecret          => "rpid_other",
                        oidcRPMetaDataOptionsIDTokenSignAlg        => "HS512",
                        oidcRPMetaDataOptionsAccessTokenJWT        => 1,
                        oidcRPMetaDataOptionsAccessTokenSignAlg    => "HS512",
                        oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                        oidcRPMetaDataOptionsBypassConsent         => 1,
                        oidcRPMetaDataOptionsRedirectUris   => 'http://client.com/',
                        oidcRPMetaDataOptionsGrantManagement => 'allowed',
                    },
                    rp_strict => {
                        oidcRPMetaDataOptionsDisplayName           => "Strict",
                        oidcRPMetaDataOptionsClientID              => "rpid_strict",
                        oidcRPMetaDataOptionsClientSecret          => "rpid_strict",
                        oidcRPMetaDataOptionsIDTokenSignAlg        => "HS512",
                        oidcRPMetaDataOptionsAccessTokenJWT        => 1,
                        oidcRPMetaDataOptionsAccessTokenSignAlg    => "HS512",
                        oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                        oidcRPMetaDataOptionsBypassConsent         => 1,
                        oidcRPMetaDataOptionsRedirectUris   => 'http://client.com/',
                        oidcRPMetaDataOptionsGrantManagement => 'required',
                    },
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            }
        }
    );
}
