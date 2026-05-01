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

sub _refresh {
    my ( $op, $client_id, $rt ) = @_;
    my $q = buildForm( {
            grant_type    => "refresh_token",
            refresh_token => $rt,
    } );
    return $op->_post(
        "/oauth2/token",
        IO::String->new($q),
        accept => 'application/json',
        length => length($q),
        custom => {
            HTTP_AUTHORIZATION => "Basic "
              . encode_base64( "$client_id:$client_id", '' ),
        },
    );
}

subtest "offline_access: grant_id survives a refresh-token grant" => sub {

    # Realistic open-banking shape: long-lived offline refresh token, the
    # client uses it for weeks and the grant_id must keep flowing through
    # every refresh.
    my $code = codeAuthorize(
        $op, $idpId,
        {
            response_type           => "code",
            scope                   => "openid profile offline_access",
            client_id               => "rpid",
            state                   => "offline-1",
            redirect_uri            => "http://client.com/",
            grant_management_action => "create",
        }
    );
    my $first =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    ok( $first->{grant_id}, "Initial grant_id present" );
    ok( $first->{refresh_token},
        "offline refresh_token issued" );
    my $offline_grant = $first->{grant_id};

    # Refresh: new AT must still carry the grant_id everywhere.
    my $second = expectJSON( _refresh( $op, "rpid", $first->{refresh_token} ) );
    is( $second->{grant_id}, $offline_grant,
        "Refresh response echoes the SAME grant_id" );

    my $payload = jwt_payload( $second->{access_token} );
    is( $payload->{grant_id}, $offline_grant,
        "Refresh-issued JWT AT carries grant_id" );

    my $intro =
      expectJSON( introspect( $op, "rpid", $second->{access_token} ) );
    is( $intro->{grant_id}, $offline_grant,
        "Refresh-issued AT introspection still carries grant_id" );

    # The grant itself is still there and queryable.
    my $get_res = gm_get( $op, "rpid", $offline_grant );
    is( $get_res->[0], 200,
        "GET on the grant still returns 200 after refreshing" );
};

subtest "Refresh-token rotation preserves grant_id across rotations" => sub {

    # Rotation enabled = each refresh issues a NEW refresh_token. The
    # plugin's storeOnRefresh hook must source from $req->data populated
    # by restoreOnTokenEndpoint, otherwise the new RT is born without
    # grant context and the chain breaks at rotation #2 (regression
    # pattern caught by Copilot on PR #20 / oidc-acr-claims).
    my $op_rot = register( 'op_rot', sub { op_with_rotation() } );
    my $id_rot = login( $op_rot, "french" );

    my $code = codeAuthorize(
        $op_rot, $id_rot,
        {
            response_type           => "code",
            scope                   => "openid profile offline_access",
            client_id               => "rpid",
            state                   => "rot-1",
            redirect_uri            => "http://client.com/",
            grant_management_action => "create",
        }
    );
    my $first =
      expectJSON( codeGrant( $op_rot, "rpid", $code, "http://client.com/" ) );
    my $rot_grant = $first->{grant_id};
    ok( $rot_grant, "Initial grant_id present (rotation flavor)" );

    # First rotation
    my $second = expectJSON( _refresh( $op_rot, "rpid", $first->{refresh_token} ) );
    isnt( $second->{refresh_token}, $first->{refresh_token},
        "Rotation issued a fresh refresh_token" );
    is( $second->{grant_id}, $rot_grant,
        "After first rotation, grant_id is preserved" );

    # Second rotation — the regression-prone one
    my $third =
      expectJSON( _refresh( $op_rot, "rpid", $second->{refresh_token} ) );
    is( $third->{grant_id}, $rot_grant,
        "After second rotation, grant_id is STILL preserved" );
    my $payload = jwt_payload( $third->{access_token} );
    is( $payload->{grant_id}, $rot_grant,
        "Twice-rotated AT JWT still carries grant_id" );
};

subtest "Subject check: another user cannot update someone else's grant" => sub {

    # User `french` already created/updated/replaced $created_grant_id at
    # this point. Now log in as a different demo user and try to use the
    # same grant_id with action=update — must be rejected.
    my $other_idp = login( $op, "dwho" );
    my $auth_res = authorize(
        $op, $other_idp,
        {
            response_type           => "code",
            scope                   => "openid",
            client_id               => "rpid",
            state                   => "wrong-user",
            redirect_uri            => "http://client.com/",
            grant_management_action => "update",
            grant_id                => $created_grant_id,
        }
    );
    expectPortalError( $auth_res, 24,
        "Cross-subject update is rejected (security)" );
};

subtest "_mergeRar deduplicates by structural equality" => sub {
    require Lemonldap::NG::Portal::Plugins::OIDCGrantManagement;
    my $existing = [
        { type => "payment_initiation", amount => "100" },
        { type => "account_information", iban => "FR76..." },
    ];
    my $new_entries = [
        { type => "payment_initiation", amount => "100" }, # dup of existing
        { type => "payment_initiation", amount => "200" }, # new
    ];
    my $merged =
      Lemonldap::NG::Portal::Plugins::OIDCGrantManagement::_mergeRar(
        $existing, $new_entries );
    is( scalar(@$merged), 3,
        "Merge keeps 3 entries (existing 2 + 1 new, 1 duplicate dropped)" );
    my @amounts = map { $_->{amount} } grep { $_->{type} eq "payment_initiation" } @$merged;
    is_deeply( [ sort @amounts ], [qw(100 200)],
        "Both payment amounts present, no duplicate of 100" );

    # Boundary: empty existing => returns new
    my $r1 = Lemonldap::NG::Portal::Plugins::OIDCGrantManagement::_mergeRar(
        undef, $new_entries );
    is_deeply( $r1, $new_entries, "Empty existing => returns new verbatim" );

    # Boundary: undef new => returns existing
    my $r2 = Lemonldap::NG::Portal::Plugins::OIDCGrantManagement::_mergeRar(
        $existing, undef );
    is_deeply( $r2, $existing, "Undef new => returns existing verbatim" );
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
                oidcServiceAllowOffline               => 1,

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
                        oidcRPMetaDataOptionsAllowOffline   => 1,
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

sub op_with_rotation {
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
                oidcServiceAllowOffline               => 1,

                oidcRPMetaDataExportedVars =>
                  { rp => { email => "mail", name => "cn" } },
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
                        oidcRPMetaDataOptionsAllowOffline          => 1,
                        oidcRPMetaDataOptionsRefreshTokenRotation  => 1,
                        oidcRPMetaDataOptionsGrantManagement       => 'allowed',
                    },
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            }
        }
    );
}
