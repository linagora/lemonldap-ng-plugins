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

my $debug = 'error';

# Initialization with global extra scopes:
# - Enrich 'profile' scope with 'department' claim
# - Define new 'corporate' scope with 'department' and 'title' claims
my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                        => $debug,
            domain                          => 'idp.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            issuerDBOpenIDConnectRule       => '$uid eq "french"',
            oidcServiceAllowOnlyDeclaredScopes => 0,
            oidcServiceGlobalExtraScopes    => {
                profile   => 'department',
                corporate => 'department title',
            },
            oidcRPMetaDataExportedVars => {
                rp => {
                    email      => "mail",
                    name       => "cn",
                    department => "department",
                    title      => "title",
                },
            },
            oidcRPMetaDataOptions => {
                rp => {
                    oidcRPMetaDataOptionsDisplayName           => "RP",
                    oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                    oidcRPMetaDataOptionsClientID              => "rpid",
                    oidcRPMetaDataOptionsIDTokenSignAlg        => "HS512",
                    oidcRPMetaDataOptionsClientSecret          => "rpid",
                    oidcRPMetaDataOptionsUserIDAttr            => "",
                    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                    oidcRPMetaDataOptionsBypassConsent         => 1,
                    oidcRPMetaDataOptionsRedirectUris => 'http://rp.com/',
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            customPlugins =>
              'Lemonldap::NG::Portal::Plugins::OIDCGlobalScopes',
        }
    }
);
my $res;

# Set session attributes for testing
# Demo user "french" has: uid=french, cn=Frédéric Accents, mail=fa@badwolf.org
# We need to inject department and title into the demo session
$op->p->setLocalMacro( 'department', sub { 'Engineering' } );
$op->p->setLocalMacro( 'title',      sub { 'Developer' } );

# Authenticate
my $query = "user=french&password=french";
ok(
    $res = $op->_post(
        "/",
        IO::String->new($query),
        accept => 'text/html',
        length => length($query),
    ),
    "Post authentication"
);
my $idpId = expectCookie($res);

# ====================================================================
# Test 1: Enriched 'profile' scope - should include 'department' claim
# ====================================================================

my $code = codeAuthorize(
    $op, $idpId,
    {
        response_type => "code",
        scope         => "openid profile",
        client_id     => "rpid",
        state         => "teststate",
        redirect_uri  => "http://rp.com/",
    }
);
ok( $code, "Got authorization code for profile scope" );

# Exchange code for access token
my $json = expectJSON( codeGrant( $op, 'rpid', $code, "http://rp.com/" ) );
my $token = $json->{access_token};
ok( $token, 'Access token present' );

# Get userinfo
$res = $op->_post(
    "/oauth2/userinfo",
    IO::String->new(''),
    accept => 'application/json',
    length => 0,
    custom => {
        HTTP_AUTHORIZATION => "Bearer $token",
    },
);
$json = expectJSON($res);
is( $json->{name}, 'Frédéric Accents', "Standard profile claim 'name' present" );
is( $json->{department}, 'Engineering',
    "Global extra claim 'department' added to profile scope" );

# ====================================================================
# Test 2: New 'corporate' scope - should include department and title
# ====================================================================

$code = codeAuthorize(
    $op, $idpId,
    {
        response_type => "code",
        scope         => "openid corporate",
        client_id     => "rpid",
        state         => "teststate2",
        redirect_uri  => "http://rp.com/",
    }
);
ok( $code, "Got authorization code for corporate scope" );

$json  = expectJSON( codeGrant( $op, 'rpid', $code, "http://rp.com/" ) );
$token = $json->{access_token};
ok( $token, 'Access token present for corporate scope' );

$res = $op->_post(
    "/oauth2/userinfo",
    IO::String->new(''),
    accept => 'application/json',
    length => 0,
    custom => {
        HTTP_AUTHORIZATION => "Bearer $token",
    },
);
$json = expectJSON($res);
is( $json->{department}, 'Engineering',
    "Global scope 'corporate' provides 'department' claim" );
is( $json->{title}, 'Developer',
    "Global scope 'corporate' provides 'title' claim" );

# Standard profile claims should NOT be present (only corporate was requested)
ok( !exists $json->{name},
    "Standard profile claim 'name' not present when only corporate requested" );

# ====================================================================
# Test 3: oidcServiceAllowOnlyDeclaredScopes - global scopes survive
# ====================================================================

# Reinitialize with oidcServiceAllowOnlyDeclaredScopes enabled
my $op2 = LLNG::Manager::Test->new( {
        ini => {
            logLevel                        => $debug,
            domain                          => 'idp.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            issuerDBOpenIDConnectRule       => '$uid eq "french"',
            oidcServiceAllowOnlyDeclaredScopes => 1,
            oidcServiceGlobalExtraScopes    => {
                corporate => 'department title',
            },
            oidcRPMetaDataExportedVars => {
                rp => {
                    email      => "mail",
                    department => "department",
                    title      => "title",
                },
            },
            oidcRPMetaDataOptions => {
                rp => {
                    oidcRPMetaDataOptionsDisplayName           => "RP",
                    oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                    oidcRPMetaDataOptionsClientID              => "rpid",
                    oidcRPMetaDataOptionsIDTokenSignAlg        => "HS512",
                    oidcRPMetaDataOptionsClientSecret          => "rpid",
                    oidcRPMetaDataOptionsUserIDAttr            => "",
                    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                    oidcRPMetaDataOptionsBypassConsent         => 1,
                    oidcRPMetaDataOptionsRedirectUris => 'http://rp.com/',
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            customPlugins =>
              'Lemonldap::NG::Portal::Plugins::OIDCGlobalScopes',
        }
    }
);

$op2->p->setLocalMacro( 'department', sub { 'Engineering' } );
$op2->p->setLocalMacro( 'title',      sub { 'Developer' } );

$query = "user=french&password=french";
ok(
    $res = $op2->_post(
        "/",
        IO::String->new($query),
        accept => 'text/html',
        length => length($query),
    ),
    "Post authentication (allowOnlyDeclaredScopes)"
);
my $idpId2 = expectCookie($res);

$code = codeAuthorize(
    $op2, $idpId2,
    {
        response_type => "code",
        scope         => "openid corporate",
        client_id     => "rpid",
        state         => "teststate3",
        redirect_uri  => "http://rp.com/",
    }
);
ok( $code,
    "Got authorization code for 'corporate' scope with allowOnlyDeclaredScopes"
);

$json  = expectJSON( codeGrant( $op2, 'rpid', $code, "http://rp.com/" ) );
$token = $json->{access_token};
ok( $token, 'Access token present with allowOnlyDeclaredScopes' );

$res = $op2->_post(
    "/oauth2/userinfo",
    IO::String->new(''),
    accept => 'application/json',
    length => 0,
    custom => {
        HTTP_AUTHORIZATION => "Bearer $token",
    },
);
$json = expectJSON($res);
is( $json->{department}, 'Engineering',
    "Global scope 'corporate' survives allowOnlyDeclaredScopes filtering" );
is( $json->{title}, 'Developer',
    "All claims from global scope present after scope filtering" );

done_testing();
