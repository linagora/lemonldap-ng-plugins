# Client-side PAR tests
# Test LemonLDAP::NG acting as an OIDC RP using PAR to authenticate
# against an external OP
use warnings;
use Test::More;
use strict;
use IO::String;
use LWP::UserAgent;
use LWP::Protocol::PSGI;
use MIME::Base64 qw/encode_base64 encode_base64url/;
use URI::QueryParam;
use Digest::SHA qw/sha256/;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my ( $op, $rp, $res );

# Set up LWP interceptor for cross-server requests
LWP::Protocol::PSGI->register(
    sub {
        my $req = Plack::Request->new(@_);
        ok( $req->uri =~ m#http://auth.((?:o|r)p).com(.*)#, ' REST request' );
        my $host = $1;
        my $url  = $2;
        my ( $r, $client );
        if ( $host eq 'op' ) {
            pass("  Request from RP to OP, endpoint $url");
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
        my $auth_header = $req->header('Authorization');
        if ( $req->method =~ /^post$/i ) {
            my $s = $req->content;
            $r = $client->_post(
                $url, IO::String->new($s),
                length => length($s),
                type   => $req->header('Content-Type'),
                ( $auth_header ? ( custom => { HTTP_AUTHORIZATION => $auth_header } ) : () ),
            );
        }
        else {
            $r = $client->_get(
                $url,
                ( $auth_header ? ( custom => { HTTP_AUTHORIZATION => $auth_header } ) : () ),
            );
        }
        return $r;
    }
);

# Initialize OP with PAR enabled
ok( $op = register( 'op', sub { op() } ), 'OP portal' );

# Get OP metadata and JWKS for RP configuration
ok( $res = $op->_get('/oauth2/jwks'), 'Get JWKS from OP' );
expectOK($res);
my $jwks = $res->[2]->[0];

ok( $res = $op->_get('/.well-known/openid-configuration'), 'Get metadata from OP' );
expectOK($res);
my $metadata = $res->[2]->[0];

# Verify PAR endpoint is in metadata
my $metadata_json = from_json($metadata);
ok( $metadata_json->{pushed_authorization_request_endpoint},
    "OP advertises PAR endpoint" );

# Reset config number for RP
&Lemonldap::NG::Handler::Main::cfgNum( 0, 0 );

subtest "End-to-end PAR flow: complete authentication via PAR" => sub {
    ok( $rp = register( 'rp', sub { rp_par( $jwks, $metadata, 'allowed' ) } ),
        'Register RP with PAR allowed' );

    # Step 1: Access RP without session - should redirect to OP via PAR
    ok( $res = $rp->_get( '/', accept => 'text/html' ), 'Unauth RP request' );

    # Step 2: Verify redirect uses PAR (request_uri instead of full params)
    my ( $url, $query ) =
      expectRedirection( $res, qr#http://auth.op.com(/oauth2/authorize)\?(.*)$# );

    my $u = URI->new;
    $u->query($query);

    # Verify request_uri is present (indicates PAR was used)
    ok( $u->query_param('request_uri'),
        "RP used PAR - request_uri is present in redirect" );
    like(
        $u->query_param('request_uri'),
        qr/^urn:ietf:params:oauth:request_uri:/,
        "request_uri has correct PAR format"
    );
    ok( $u->query_param('client_id'), "client_id is present" );
    # With PAR, only client_id and request_uri should be in the URL
    ok( !$u->query_param('redirect_uri'),
        "redirect_uri is NOT in URL (it's in PAR)" );
    ok( !$u->query_param('scope'),
        "scope is NOT in URL (it's in PAR)" );

    # Step 3: OP receives authorize request and shows login form
    ok( $res = $op->_get( $url, query => $query, accept => 'text/html' ),
        "Push PAR authorize request to OP" );
    expectOK($res);

    # Step 4: User authenticates at OP
    my $op_query = "user=french&password=french&$query";
    ok(
        $res = $op->_post(
            $url,
            IO::String->new($op_query),
            accept => 'text/html',
            length => length($op_query),
        ),
        "Authenticate at OP"
    );
    my $op_id = expectCookie($res);

    # Step 5: OP redirects back to RP with authorization code
    ($query) = expectRedirection( $res, qr#^http://auth.rp.com/?\?(.*)$# );
    ok( $query =~ /code=/, "Authorization code present in redirect" );

    # Step 6: RP exchanges code for tokens and creates session
    ok( $res = $rp->_get( '/', query => $query, accept => 'text/html' ),
        'Complete OIDC callback at RP' );
    my $rp_id = expectCookie($res);
    ok( $rp_id, "RP session created" );

    # Step 7: Verify session contains user information from OP
    my $rp_session = getSession($rp_id);
    ok( $rp_session, "Can retrieve RP session" );
    is( $rp_session->data->{uid}, 'french', "Session has correct uid" );
    is( $rp_session->data->{cn}, 'Frédéric Accents', "Session has correct cn (UTF-8)" );
    ok( $rp_session->data->{mail}, "Session has mail attribute" );

    # Step 8: Verify authenticated access works
    ok( $res = $rp->_get( '/', cookie => "lemonldap=$rp_id", accept => 'text/html' ),
        'Authenticated request to RP' );
    expectOK($res);

    # Verify we're logged in (page should show user info, not login form)
    ok( $res->[2]->[0] !~ /trspan="connect"/, "Not showing login form" );
};

subtest "End-to-end PAR flow with required mode" => sub {
    &Lemonldap::NG::Handler::Main::cfgNum( 0, 0 );
    ok( $rp = register( 'rp', sub { rp_par( $jwks, $metadata, 'required' ) } ),
        'Register RP with PAR required' );

    # Step 1: Access RP - should redirect to OP via PAR
    ok( $res = $rp->_get( '/', accept => 'text/html' ), 'Unauth RP request' );

    # Step 2: Verify PAR is used
    my ( $url, $query ) =
      expectRedirection( $res, qr#http://auth.op.com(/oauth2/authorize)\?(.*)$# );

    my $u = URI->new;
    $u->query($query);
    ok( $u->query_param('request_uri'), "PAR used - request_uri present" );

    # Step 3: Authenticate at OP
    ok( $res = $op->_get( $url, query => $query, accept => 'text/html' ),
        "OP receives PAR authorize request" );
    expectOK($res);

    my $op_query = "user=french&password=french&$query";
    ok(
        $res = $op->_post(
            $url,
            IO::String->new($op_query),
            accept => 'text/html',
            length => length($op_query),
        ),
        "Authenticate at OP"
    );
    my $op_id = expectCookie($res);

    # Step 4: Complete flow at RP
    ($query) = expectRedirection( $res, qr#^http://auth.rp.com/?\?(.*)$# );
    ok( $res = $rp->_get( '/', query => $query, accept => 'text/html' ),
        'Complete OIDC callback at RP' );
    my $rp_id = expectCookie($res);
    ok( $rp_id, "RP session created with PAR required" );

    # Step 5: Verify session
    my $rp_session = getSession($rp_id);
    is( $rp_session->data->{uid}, 'french', "Session has correct uid" );
};

subtest "End-to-end flow without PAR (normal OIDC)" => sub {
    &Lemonldap::NG::Handler::Main::cfgNum( 0, 0 );
    ok( $rp = register( 'rp', sub { rp_par( $jwks, $metadata, '' ) } ),
        'Register RP with PAR disabled' );

    # Step 1: Access RP - should redirect to OP with all params in URL
    ok( $res = $rp->_get( '/', accept => 'text/html' ), 'Unauth RP request' );

    my ( $url, $query ) =
      expectRedirection( $res, qr#http://auth.op.com(/oauth2/authorize)\?(.*)$# );

    my $u = URI->new;
    $u->query($query);

    # Verify PAR is NOT used - all params should be in URL
    ok( !$u->query_param('request_uri'),
        "PAR not used - no request_uri" );
    ok( $u->query_param('client_id'),     "client_id in URL" );
    ok( $u->query_param('redirect_uri'),  "redirect_uri in URL" );
    ok( $u->query_param('response_type'), "response_type in URL" );
    ok( $u->query_param('scope'),         "scope in URL" );

    # Step 2: Complete authentication at OP
    ok( $res = $op->_get( $url, query => $query, accept => 'text/html' ),
        "OP receives normal authorize request" );
    expectOK($res);

    my $op_query = "user=french&password=french&$query";
    ok(
        $res = $op->_post(
            $url,
            IO::String->new($op_query),
            accept => 'text/html',
            length => length($op_query),
        ),
        "Authenticate at OP"
    );
    my $op_id = expectCookie($res);

    # Step 3: Complete flow at RP
    ($query) = expectRedirection( $res, qr#^http://auth.rp.com/?\?(.*)$# );
    ok( $res = $rp->_get( '/', query => $query, accept => 'text/html' ),
        'Complete OIDC callback at RP' );
    my $rp_id = expectCookie($res);
    ok( $rp_id, "RP session created without PAR" );

    # Step 4: Verify session
    my $rp_session = getSession($rp_id);
    is( $rp_session->data->{uid}, 'french', "Session has correct uid" );
};

clean_sessions();
done_testing();

sub rp_par {
    my ( $jwks, $metadata, $use_par ) = @_;
    return LLNG::Manager::Test->new( {
            ini => {
                logLevel                   => 'error',
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
                        mail => "email",
                    }
                },
                oidcOPMetaDataOptions => {
                    op => {
                        oidcOPMetaDataOptionsCheckJWTSignature => 1,
                        oidcOPMetaDataOptionsJWKSTimeout       => 0,
                        oidcOPMetaDataOptionsClientSecret      => "rp",
                        oidcOPMetaDataOptionsScope      => "openid profile email",
                        oidcOPMetaDataOptionsClientID   => "rp",
                        oidcOPMetaDataOptionsUseNonce   => 1,
                        oidcOPMetaDataOptionsUsePAR     => $use_par,
                        oidcOPMetaDataOptionsConfigurationURI =>
                          "https://auth.op.com/.well-known/openid-configuration"
                    }
                },
                oidcOPMetaDataJWKS => {
                    op => $jwks,
                },
                oidcOPMetaDataJSON => {
                    op => $metadata,
                },
            }
        }
    );
}

sub op {
    return LLNG::Manager::Test->new( {
            ini => {
                domain                          => 'idp.com',
                portal                          => 'http://auth.op.com/',
                authentication                  => 'Demo',
                userDB                          => 'Same',
                customPlugins                   => '::Plugins::OIDCPushedAuthRequest',
                issuerDBOpenIDConnectActivation => "1",
                restSessionServer               => 1,

                # PAR configuration
                oidcServiceMetaDataPushedAuthURI => 'par',
                oidcServicePushedAuthExpiration  => 60,

                oidcRPMetaDataExportedVars => {
                    rp => {
                        email  => "mail",
                        name   => "cn",
                        groups => "groups",
                    },
                },
                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcRPMetaDataOptions                 => {
                    rp => {
                        oidcRPMetaDataOptionsDisplayName           => "RP",
                        oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                        oidcRPMetaDataOptionsClientID              => "rp",
                        oidcRPMetaDataOptionsIDTokenSignAlg        => "RS256",
                        oidcRPMetaDataOptionsBypassConsent         => 1,
                        oidcRPMetaDataOptionsClientSecret          => "rp",
                        oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                        oidcRPMetaDataOptionsRedirectUris          =>
                          'http://auth.rp.com/?openidconnectcallback=1',
                        oidcRPMetaDataOptionsPAR                   => 'allowed',
                    },
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            }
        }
    );
}
