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

# Fixture: an RP that declares ONLY `name` in its Exported Attributes.
# Global scope `corporate` asks for three claims:
#   - department (not declared by the RP → exercised via
#                 oidcServiceGlobalClaimMapping with a different
#                 session attribute name)
#   - title      (not declared by the RP → exercised via identity
#                 fallback: claim name == session attribute name)
#   - name       (declared by the RP → per-RP declaration must win)
my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                           => $debug,
            domain                             => 'idp.com',
            portal                             => 'http://auth.op.com/',
            authentication                     => 'Demo',
            userDB                             => 'Same',
            issuerDBOpenIDConnectActivation    => 1,
            issuerDBOpenIDConnectRule          => '$uid eq "french"',
            oidcServiceAllowOnlyDeclaredScopes => 0,
            oidcServiceGlobalExtraScopes       => {
                corporate => 'department title name',
            },
            oidcServiceGlobalClaimMapping => {

                # claim `department` should pull session attr `dept`
                department => 'dept',
            },
            oidcRPMetaDataExportedVars => {
                rp => {

                    # Only `name` is declared here.
                    name => 'cn',
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

# Inject session attributes the plugin is expected to resolve.
#   - `dept`  is the explicit-mapping target for claim `department`
#   - `title` is the identity-fallback target for claim `title`
$op->p->setLocalMacro( 'dept',  sub { 'Engineering' } );
$op->p->setLocalMacro( 'title', sub { 'Developer' } );

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

# Request the corporate scope
my $code = codeAuthorize(
    $op, $idpId,
    {
        response_type => "code",
        scope         => "openid corporate",
        client_id     => "rpid",
        state         => "teststate",
        redirect_uri  => "http://rp.com/",
    }
);
ok( $code, "Got authorization code for corporate scope" );

my $json = expectJSON( codeGrant( $op, 'rpid', $code, "http://rp.com/" ) );
my $token = $json->{access_token};
ok( $token, 'Access token present' );

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

# Claim 1: explicit global mapping (department => dept)
is( $json->{department}, 'Engineering',
    "Explicit global mapping: claim 'department' resolved via session attr 'dept'"
);

# Claim 2: identity fallback (claim name == session attr name)
is( $json->{title}, 'Developer',
    "Identity fallback: claim 'title' resolved via session attr 'title'" );

# Claim 3: RP declaration wins — `name` was declared with cn
is( $json->{name}, 'Frédéric Accents',
    "RP declaration takes precedence over global mapping" );

# ====================================================================
# Second fixture: confirm the plugin does NOT silently pull an unrelated
# session attribute when neither the RP nor the mapping declares a claim
# and the identity lookup also fails.
# ====================================================================

my $op2 = LLNG::Manager::Test->new( {
        ini => {
            logLevel                           => $debug,
            domain                             => 'idp.com',
            portal                             => 'http://auth.op.com/',
            authentication                     => 'Demo',
            userDB                             => 'Same',
            issuerDBOpenIDConnectActivation    => 1,
            issuerDBOpenIDConnectRule          => '$uid eq "french"',
            oidcServiceAllowOnlyDeclaredScopes => 0,
            oidcServiceGlobalExtraScopes       => {
                corporate => 'nonexistent',
            },
            oidcServiceGlobalClaimMapping => {},
            oidcRPMetaDataExportedVars    => {
                rp => { email => 'mail' },
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

$query = "user=french&password=french";
ok(
    $res = $op2->_post(
        "/",
        IO::String->new($query),
        accept => 'text/html',
        length => length($query),
    ),
    "Post authentication (unresolvable claim)"
);
my $idpId2 = expectCookie($res);

$code = codeAuthorize(
    $op2, $idpId2,
    {
        response_type => "code",
        scope         => "openid corporate",
        client_id     => "rpid",
        state         => "teststate2",
        redirect_uri  => "http://rp.com/",
    }
);
ok( $code, "Got authorization code (unresolvable claim)" );

$json  = expectJSON( codeGrant( $op2, 'rpid', $code, "http://rp.com/" ) );
$token = $json->{access_token};
ok( $token, 'Access token present (unresolvable claim)' );

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
ok( !exists $json->{nonexistent},
    "Unresolvable claim is silently skipped, not emitted with empty value" );

done_testing();
