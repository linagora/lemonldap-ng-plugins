# End-to-end PAR test with private_key_jwt authentication
# Test LemonLDAP::NG acting as an OIDC RP using PAR with private_key_jwt
# to authenticate against an external OP
use lib 'inc';
use warnings;
use Test::More;
use strict;
use IO::String;
use LWP::UserAgent;
use LWP::Protocol::PSGI;
use MIME::Base64;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my $debug = 'error';
my ( $op, $rp, $res );

# Set up LWP interceptor for cross-server requests
LWP::Protocol::PSGI->register(
    sub {
        my $req = Plack::Request->new(@_);

        # Handle early requests to RP before it's ready (during OP initial load)
        if ( $req->uri =~ m#http://auth.rp.com# && !$rp ) {
            # Return 500 silently - OP will retry after reload
            return [ 500, [], ['RP not ready'] ];
        }

        ok( $req->uri =~ m#http://auth.((?:o|r)p).com(.*)#, ' REST request' );
        my $host = $1;
        my $url  = $2;
        my ( $r, $client );
        count(1);
        if ( $host eq 'op' ) {
            pass("  Request from RP to OP,     endpoint $url");
            $client = $op;
        }
        elsif ( $host eq 'rp' ) {
            pass('  Request from OP to RP');
            $client = $rp;
        }
        else {
            fail('  Aborting REST request (external)');
            return [ 500, [], [] ];
        }
        count(1);
        if ( $req->method =~ /^post$/i ) {
            my $s = $req->content;
            ok(
                $r = $client->_post(
                    $url, IO::String->new($s),
                    length => length($s),
                    type   => $req->header('Content-Type'),
                ),
                '  Execute request'
            );
        }
        else {
            ok(
                $r = $client->_get(
                    $url,
                    (
                        $req->header('Authorization')
                        ? (
                            custom => {
                                HTTP_AUTHORIZATION =>
                                  $req->header('Authorization'),
                            }
                          )
                        : ()
                    ),
                ),
                '  Execute request'
            );
        }
        # PAR endpoint returns 201, others return 200
        ok( $r->[0] == 200 || $r->[0] == 201, '  Response is 200 or 201' );
        count(2);
        if ( $url !~ /blogout/ ) {
            ok(
                getHeader( $r, 'Content-Type' ) =~
                  m#^application/(?:json|jwt)#,
                '  Content is JSON'
            ) or explain( $r->[1], 'Content-Type => application/json' );
            count(1);
        }
        return $r;
    }
);

# Initialization
$op = register( 'op', \&op );

ok( $res = $op->_get('/oauth2/jwks'), 'Get JWKS,     endpoint /oauth2/jwks' );
expectOK($res);
my $jwks = $res->[2]->[0];

ok(
    $res = $op->_get('/.well-known/openid-configuration'),
    'Get metadata, endpoint /.well-known/openid-configuration'
);
expectOK($res);
my $metadata = $res->[2]->[0];
count(2);

# Verify PAR endpoint is advertised
my $metadata_json = from_json($metadata);
ok( $metadata_json->{pushed_authorization_request_endpoint},
    "OP advertises PAR endpoint" );
count(1);

$rp = register( 'rp', sub { rp( $jwks, $metadata ) } );

# Reload OP so it can fetch RP's JWKS
$op = register( 'op', \&op );

# Verify that RP published its keys
ok( $res = $rp->_get('/oauth2/jwks'), 'RP publish its keys' );
my $rpKeys = expectJSON($res);
my $rpSigKey;
ok( (
              ref($rpKeys)
          and ref( $rpKeys->{keys} ) eq 'ARRAY'
          and $rpSigKey = $rpKeys->{keys}->[0]
    ),
    'Get RP sig key'
);
count(2);

# Query RP for auth - RP will use PAR with private_key_jwt
ok( $res = $rp->_get( '/', accept => 'text/html' ), 'Unauth RP request' );
count(1);

# RP should redirect to OP using PAR (request_uri instead of full params)
my ( $url, $query ) =
  expectRedirection( $res, qr#http://auth.op.com(/oauth2/authorize)\?(.*)$# );

# Verify PAR was used
my $u = URI->new;
$u->query($query);
ok( $u->query_param('request_uri'), "PAR used - request_uri present" );
like(
    $u->query_param('request_uri'),
    qr/^urn:ietf:params:oauth:request_uri:/,
    "request_uri has correct PAR format"
);
ok( $u->query_param('client_id'), "client_id is present" );
count(3);

# Push request to OP
ok( $res = $op->_get( $url, query => $query, accept => 'text/html' ),
    "Push PAR request to OP,     endpoint $url" );
count(1);
expectOK($res);

# Try to authenticate to OP
$query = "user=french&password=french&$query";
ok(
    $res = $op->_post(
        $url,
        IO::String->new($query),
        accept => 'text/html',
        length => length($query),
    ),
    "Post authentication,        endpoint $url"
);
count(1);
my $idpId = expectCookie($res);

# With bypassConsent=1, we should get immediate redirect
($query) = expectRedirection( $res, qr#^http://auth.rp.com/?\?(.*)$# );

# Push OP response to RP - RP will use private_key_jwt for token exchange
ok( $res = $rp->_get( '/', query => $query, accept => 'text/html' ),
    'Call openidconnectcallback on RP' );
count(1);
my $spId = expectCookie($res);
ok( $spId, "RP session created with PAR + private_key_jwt" );
count(1);

# Verify session contains user information
my $rp_session = getSession($spId);
ok( $rp_session, "Can retrieve RP session" );
is( $rp_session->data->{uid}, 'french', "Session has correct uid" );
count(2);

# Logout initiated by OP

# Reset conf to make sure lazy loading works during logout (#3014)
withHandler( 'op', sub { $op->p->HANDLER->checkConf(1) } );

ok(
    $res = $op->_get(
        '/',
        query  => 'logout',
        cookie => "lemonldap=$idpId",
        accept => 'text/html'
    ),
    'Query OP for logout'
);
count(1);
expectOK($res);

# Test if logout is done
ok(
    $res = $op->_get(
        '/', cookie => "lemonldap=$idpId",
    ),
    'Test if user is reject on OP'
);
count(1);
expectReject($res);

ok(
    $res = $rp->_get(
        '/',
        cookie => "lemonldap=$spId",
        accept => 'text/html'
    ),
    'Test if user is reject on RP'
);
count(1);
expectRedirection( $res, qr#http://auth.op.com(/oauth2/authorize)\?(.*)$# );

clean_sessions();
done_testing( count() );

sub op {
    return LLNG::Manager::Test->new( {
            ini => {
                logLevel                        => $debug,
                domain                          => 'idp.com',
                portal                          => 'http://auth.op.com/',
                authentication                  => 'Demo',
                userDB                          => 'Same',
                customPlugins                   => '::Plugins::OIDCPushedAuthRequest',
                issuerDBOpenIDConnectActivation => "1",

                # PAR configuration
                oidcServiceMetaDataPushedAuthURI => 'par',
                oidcServicePushedAuthExpiration  => 60,

                oidcRPMetaDataExportedVars => {
                    rp => {
                        email       => "mail",
                        family_name => "cn",
                        name        => "cn"
                    }
                },
                oidcServiceAllowHybridFlow            => 1,
                oidcServiceAllowImplicitFlow          => 1,
                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcRPMetaDataOptions                 => {
                    rp => {
                        oidcRPMetaDataOptionsDisplayName           => "RP",
                        oidcRPMetaDataOptionsClientID              => "rpid",
                        oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                        oidcRPMetaDataOptionsIDTokenSignAlg        => "RS256",
                        oidcRPMetaDataOptionsBypassConsent         => 1,
                        oidcRPMetaDataOptionsUserIDAttr            => "",
                        oidcRPMetaDataOptionsUserInfoSignAlg       => 'RS256',
                        oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                        oidcRPMetaDataOptionsLogoutUrl             =>
                          'http://auth.rp.com/oauth2/blogout',
                        oidcRPMetaDataOptionsLogoutType            => 'back',
                        oidcRPMetaDataOptionsLogoutSessionRequired => 1,
                        oidcRPMetaDataOptionsRedirectUris          =>
                          'http://auth.rp.com/?openidconnectcallback=1',
                        oidcRPMetaDataOptionsJwksUri =>
                          'http://auth.rp.com/oauth2/jwks',
                        oidcRPMetaDataOptionsPAR => 'allowed',
                    }
                },
                oidcOPMetaDataOptions           => {},
                oidcOPMetaDataJSON              => {},
                oidcOPMetaDataJWKS              => {},
                oidcServiceMetaDataAuthnContext => {
                    'loa-4' => 4,
                    'loa-1' => 1,
                    'loa-5' => 5,
                    'loa-2' => 2,
                    'loa-3' => 3
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            }
        }
    );
}

sub rp {
    my ( $jwks, $metadata ) = @_;
    return LLNG::Manager::Test->new( {
            ini => {
                logLevel                   => $debug,
                domain                     => 'rp.com',
                portal                     => 'http://auth.rp.com/',
                authentication             => 'OpenIDConnect',
                userDB                     => 'Same',
                customPlugins              => '::Plugins::OIDCPushedAuthRequestClient',
                restSessionServer          => 1,
                oidcOPMetaDataExportedVars => {
                    op => {
                        cn   => "name",
                        uid  => "sub",
                        sn   => "family_name",
                        mail => "email"
                    }
                },
                oidcServiceMetaDataBackChannelURI => 'blogout',
                oidcOPMetaDataOptions             => {
                    op => {
                        oidcOPMetaDataOptionsCheckJWTSignature => 1,
                        oidcOPMetaDataOptionsJWKSTimeout       => 0,
                        oidcOPMetaDataOptionsScope        => "openid profile",
                        oidcOPMetaDataOptionsStoreIDToken => 0,
                        oidcOPMetaDataOptionsDisplay      => "",
                        oidcOPMetaDataOptionsClientID     => "rpid",
                        oidcOPMetaDataOptionsConfigurationURI =>
"https://auth.op.com/.well-known/openid-configuration",
                        # Use private_key_jwt for PAR and token endpoints
                        oidcOPMetaDataOptionsTokenEndpointAuthMethod =>
                          'private_key_jwt',
                        # Enable PAR (required mode)
                        oidcOPMetaDataOptionsUsePAR => 'required',
                    }
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
                oidcServiceKeyIdSig      => 'aabbcc',
                oidcOPMetaDataJWKS       => {
                    op => $jwks,
                },
                oidcOPMetaDataJSON => {
                    op => $metadata,
                }
            }
        }
    );
}
