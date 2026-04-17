use warnings;
use Test::More;
use strict;
use IO::String;
use LWP::UserAgent;
use LWP::Protocol::PSGI;
use MIME::Base64;
use JSON qw(from_json to_json);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my $debug = 'error';

# Track CIBA notification requests
my @ciba_notifications;

# Track ping notifications to RP
my @ping_notifications;

# Mock the external authentication channel and RP ping endpoint
LWP::Protocol::PSGI->register(
    sub {
        my $req = Plack::Request->new(@_);
        if ( $req->uri =~ m#^http://ciba-channel/notify# ) {

            # Store the notification for later verification
            my $body = from_json( $req->content );
            push @ciba_notifications, $body;

            return [
                200, [ 'Content-Type' => 'application/json' ],
                ['{"result":"ok"}']
            ];
        }
        elsif ( $req->uri =~ m#^http://rp-ping.example.com/ciba/notify# ) {

            # Store ping notification for RP
            my $body = from_json( $req->content );
            push @ping_notifications, $body;

            return [ 204, [], [] ];
        }
        return [ 404, [], ['Not found'] ];
    }
);

# Initialization
my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                        => $debug,
            domain                          => 'op.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            customPlugins                   => '::Plugins::OIDCCIBA',
            issuerDBOpenIDConnectActivation => 1,
            oidcRPMetaDataExportedVars      => {
                rp => {
                    "email" => "mail",
                    "name"  => "cn",
                }
            },
            oidcRPMetaDataOptions => {
                rp => {
                    oidcRPMetaDataOptionsDisplayName           => "RP",
                    oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                    oidcRPMetaDataOptionsIDTokenSignAlg        => "RS256",
                    oidcRPMetaDataOptionsClientID              => "rpid",
                    oidcRPMetaDataOptionsClientSecret          => "rpsecret",
                    oidcRPMetaDataOptionsUserIDAttr            => "",
                    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                    oidcRPMetaDataOptionsBypassConsent         => 1,
                    oidcRPMetaDataOptionsRefreshToken          => 1,
                    oidcRPMetaDataOptionsAllowCIBA             => 1,
                    oidcRPMetaDataOptionsCIBAMode              => 'poll',
                },
                rp_no_ciba => {
                    oidcRPMetaDataOptionsDisplayName           => "RP No CIBA",
                    oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                    oidcRPMetaDataOptionsIDTokenSignAlg        => "RS256",
                    oidcRPMetaDataOptionsClientID              => "rpid2",
                    oidcRPMetaDataOptionsClientSecret          => "rpsecret2",
                    oidcRPMetaDataOptionsUserIDAttr            => "",
                    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                    oidcRPMetaDataOptionsBypassConsent         => 1,
                    oidcRPMetaDataOptionsAllowCIBA             => 0,
                },
                rp_ping => {
                    oidcRPMetaDataOptionsDisplayName       => "RP Ping Mode",
                    oidcRPMetaDataOptionsIDTokenExpiration => 3600,
                    oidcRPMetaDataOptionsIDTokenSignAlg    => "RS256",
                    oidcRPMetaDataOptionsClientID          => "rpid_ping",
                    oidcRPMetaDataOptionsClientSecret      => "rpsecret_ping",
                    oidcRPMetaDataOptionsUserIDAttr        => "",
                    oidcRPMetaDataOptionsAccessTokenExpiration    => 3600,
                    oidcRPMetaDataOptionsBypassConsent            => 1,
                    oidcRPMetaDataOptionsRefreshToken             => 1,
                    oidcRPMetaDataOptionsAllowCIBA                => 1,
                    oidcRPMetaDataOptionsCIBAMode                 => 'ping',
                    oidcRPMetaDataOptionsCIBANotificationEndpoint =>
                      'http://rp-ping.example.com/ciba/notify',
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,

            # CIBA configuration
            oidcServiceMetaDataCibaURI              => 'bc-authorize',
            oidcServiceCibaExpiration               => 120,
            oidcServiceCibaMaxExpiration            => 300,
            oidcServiceCibaInterval                 => 5,
            oidcServiceCibaAuthenticationChannelUrl =>
              'http://ciba-channel/notify',
            oidcServiceCibaAuthenticationChannelSecret => 'channel_secret',
            oidcServiceCibaCallbackSecret              => 'callback_secret',
            oidcServiceMetaDataCibaCallbackURI         => 'ciba-callback',
        }
    }
);

my $res;

subtest "CIBA metadata" => sub {
    $res = $op->_get( "/.well-known/openid-configuration",
        accept => 'application/json', );
    my $metadata = expectJSON($res);

    ok( $metadata->{backchannel_authentication_endpoint},
        "CIBA endpoint in metadata" );
    like( $metadata->{backchannel_authentication_endpoint},
        qr/bc-authorize/, "CIBA endpoint URL correct" );

    ok( $metadata->{backchannel_token_delivery_modes_supported},
        "CIBA delivery modes in metadata" );
    is_deeply(
        $metadata->{backchannel_token_delivery_modes_supported},
        [ 'poll', 'ping' ],
        "CIBA delivery modes correct"
    );

    ok(
        grep { $_ eq 'urn:openid:params:grant-type:ciba' }
          @{ $metadata->{grant_types_supported} },
        "CIBA grant type in supported grants"
    );
};

subtest "CIBA backchannel authentication" => sub {
    @ciba_notifications = ();

    my $query = buildForm( {
            client_id     => 'rpid',
            client_secret => 'rpsecret',
            scope         => 'profile email',
            login_hint    => 'dwho',
        }
    );

    $res = $op->_post(
        "/oauth2/bc-authorize",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    expectReject( $res, 400, "invalid_scope" );

    $query = buildForm( {
            client_id     => 'rpid',
            client_secret => 'rpsecret',
            scope         => 'openid profile',
        }
    );

    $res = $op->_post(
        "/oauth2/bc-authorize",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    expectReject( $res, 400, "invalid_request" );

    $query = buildForm( {
            client_id     => 'rpid2',
            client_secret => 'rpsecret2',
            scope         => 'openid profile',
            login_hint    => 'dwho',
        }
    );

    $res = $op->_post(
        "/oauth2/bc-authorize",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    expectReject( $res, 400, "unauthorized_client" );

    $query = buildForm( {
            client_id       => 'rpid',
            client_secret   => 'rpsecret',
            scope           => 'openid profile email',
            login_hint      => 'dwho',
            binding_message => 'Confirm payment of 50 EUR',
        }
    );

    $res = $op->_post(
        "/oauth2/bc-authorize",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    my $payload = expectJSON($res);

    ok( $payload->{auth_req_id}, "Got auth_req_id" );
    ok( $payload->{expires_in},  "Got expires_in" );
    ok( $payload->{interval},    "Got interval" );

    # Verify notification was sent
    is( scalar(@ciba_notifications), 1, "One notification sent" );
    is( $ciba_notifications[0]->{login_hint},
        'dwho', "Notification contains login_hint" );
    is(
        $ciba_notifications[0]->{binding_message},
        'Confirm payment of 50 EUR',
        "Notification contains binding_message"
    );

    # Store auth_req_id for later tests
    $ENV{CIBA_AUTH_REQ_ID} = $payload->{auth_req_id};
};

subtest "CIBA token endpoint - pending" => sub {
    my $auth_req_id = $ENV{CIBA_AUTH_REQ_ID};
    ok( $auth_req_id, "Have auth_req_id from previous test" );

    my $query = buildForm( {
            client_id     => 'rpid',
            client_secret => 'rpsecret',
            grant_type    => 'urn:openid:params:grant-type:ciba',
            auth_req_id   => $auth_req_id,
        }
    );

    $res = $op->_post(
        "/oauth2/token",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    expectReject( $res, 400, "authorization_pending" );

    # Poll again immediately - should get slow_down
    $res = $op->_post(
        "/oauth2/token",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    expectReject( $res, 400, "slow_down" );
};

subtest "CIBA callback - approve" => sub {
    my $auth_req_id = $ENV{CIBA_AUTH_REQ_ID};
    ok( $auth_req_id, "Have auth_req_id from previous test" );

    my $callback_body = to_json( {
            auth_req_id => $auth_req_id,
            status      => 'approved',
            sub         => 'dwho',
        }
    );

    $res = $op->_post(
        "/oauth2/ciba-callback",
        IO::String->new($callback_body),
        accept => 'application/json',
        length => length($callback_body),
        type   => 'application/json',
        custom => {
            HTTP_AUTHORIZATION => "Bearer callback_secret",
        },
    );
    my $payload = expectJSON($res);
    is( $payload->{status}, 'ok', "Callback accepted" );
};

subtest "CIBA token endpoint - success" => sub {
    my $auth_req_id = $ENV{CIBA_AUTH_REQ_ID};
    ok( $auth_req_id, "Have auth_req_id from previous test" );

    my $query = buildForm( {
            client_id     => 'rpid',
            client_secret => 'rpsecret',
            grant_type    => 'urn:openid:params:grant-type:ciba',
            auth_req_id   => $auth_req_id,
        }
    );

    $res = $op->_post(
        "/oauth2/token",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    my $payload = expectJSON($res);

    ok( $payload->{access_token}, "Got access_token" );
    ok( $payload->{id_token},     "Got id_token" );
    is( $payload->{token_type}, 'Bearer', "Token type is Bearer" );
    ok( $payload->{expires_in}, "Got expires_in" );

    # Verify ID token
    my $id_token_payload = getJWTPayload( $payload->{id_token} );
    is( $id_token_payload->{sub}, 'dwho', "ID token sub is dwho" );
};

subtest "CIBA callback - unauthorized" => sub {

    # First create a new CIBA request
    my $query = buildForm( {
            client_id     => 'rpid',
            client_secret => 'rpsecret',
            scope         => 'openid',
            login_hint    => 'dwho',
        }
    );

    $res = $op->_post(
        "/oauth2/bc-authorize",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    my $payload      = expectJSON($res);
    my $auth_req_id2 = $payload->{auth_req_id};

    # Try callback without authorization
    my $callback_body = to_json( {
            auth_req_id => $auth_req_id2,
            status      => 'approved',
        }
    );

    $res = $op->_post(
        "/oauth2/ciba-callback",
        IO::String->new($callback_body),
        accept => 'application/json',
        length => length($callback_body),
        type   => 'application/json',
    );
    expectReject( $res, 401, "unauthorized" );

    # Try callback with wrong secret
    $res = $op->_post(
        "/oauth2/ciba-callback",
        IO::String->new($callback_body),
        accept => 'application/json',
        length => length($callback_body),
        type   => 'application/json',
        custom => {
            HTTP_AUTHORIZATION => "Bearer wrong_secret",
        },
    );
    expectReject( $res, 401, "unauthorized" );
};

subtest "CIBA callback - deny" => sub {

    # Create a new CIBA request
    my $query = buildForm( {
            client_id     => 'rpid',
            client_secret => 'rpsecret',
            scope         => 'openid',
            login_hint    => 'dwho',
        }
    );

    $res = $op->_post(
        "/oauth2/bc-authorize",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    my $payload     = expectJSON($res);
    my $auth_req_id = $payload->{auth_req_id};

    my $callback_body = to_json( {
            auth_req_id => $auth_req_id,
            status      => 'denied',
        }
    );

    $res = $op->_post(
        "/oauth2/ciba-callback",
        IO::String->new($callback_body),
        accept => 'application/json',
        length => length($callback_body),
        type   => 'application/json',
        custom => {
            HTTP_AUTHORIZATION => "Bearer callback_secret",
        },
    );
    my $cb_payload = expectJSON($res);
    is( $cb_payload->{status}, 'ok', "Callback accepted" );

    $query = buildForm( {
            client_id     => 'rpid',
            client_secret => 'rpsecret',
            grant_type    => 'urn:openid:params:grant-type:ciba',
            auth_req_id   => $auth_req_id,
        }
    );

    $res = $op->_post(
        "/oauth2/token",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    expectReject( $res, 400, "access_denied" );
};

subtest "CIBA with wrong RP" => sub {

    my $query = buildForm( {
            client_id     => 'rpid',
            client_secret => 'rpsecret',
            scope         => 'openid',
            login_hint    => 'dwho',
        }
    );

    $res = $op->_post(
        "/oauth2/bc-authorize",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    my $payload     = expectJSON($res);
    my $auth_req_id = $payload->{auth_req_id};

    # Approve it
    my $callback_body = to_json( {
            auth_req_id => $auth_req_id,
            status      => 'approved',
            sub         => 'dwho',
        }
    );

    $res = $op->_post(
        "/oauth2/ciba-callback",
        IO::String->new($callback_body),
        accept => 'application/json',
        length => length($callback_body),
        type   => 'application/json',
        custom => {
            HTTP_AUTHORIZATION => "Bearer callback_secret",
        },
    );
    expectJSON($res);

    # Try to get token with different RP - should fail
    $query = buildForm( {
            client_id     => 'rpid2',
            client_secret => 'rpsecret2',
            grant_type    => 'urn:openid:params:grant-type:ciba',
            auth_req_id   => $auth_req_id,
        }
    );

    $res = $op->_post(
        "/oauth2/token",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    expectReject( $res, 400, "invalid_grant" );
};

subtest "CIBA with invalid auth_req_id" => sub {
    my $query = buildForm( {
            client_id     => 'rpid',
            client_secret => 'rpsecret',
            grant_type    => 'urn:openid:params:grant-type:ciba',
            auth_req_id   => 'invalid_auth_req_id_12345',
        }
    );

    $res = $op->_post(
        "/oauth2/token",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    expectReject( $res, 400, "invalid_grant" );
};

subtest "CIBA direct authentication" => sub {

    # First, log in the user
    $res = $op->_post(
        '/',
        IO::String->new('user=dwho&password=dwho'),
        length => 23,
        accept => 'text/html',
    );
    my $id = expectCookie($res);

    # CIBA request with login_hint matching authenticated user
    my $query = buildForm( {
            client_id     => 'rpid',
            client_secret => 'rpsecret',
            scope         => 'openid profile',
            login_hint    => 'dwho',
        }
    );

    $res = $op->_post(
        "/oauth2/bc-authorize",
        IO::String->new($query),
        cookie => "lemonldap=$id",
        accept => 'application/json',
        length => length($query),
    );
    my $payload = expectJSON($res);

    # Should get tokens directly, not auth_req_id
    ok( $payload->{access_token}, "Got access_token directly" );
    ok( $payload->{id_token},     "Got id_token directly" );
    is( $payload->{token_type}, 'Bearer', "Token type is Bearer" );

    # Verify ID token
    my $id_token_payload = getJWTPayload( $payload->{id_token} );
    is( $id_token_payload->{sub}, 'dwho', "ID token sub is dwho" );

    # Logout
    $op->_get( '/', cookie => "lemonldap=$id", query => 'logout' );
};

subtest "CIBA mismatched login_hint" => sub {
    @ciba_notifications = ();    # Reset notifications

    # Log in as dwho
    $res = $op->_post(
        '/',
        IO::String->new('user=dwho&password=dwho'),
        length => 23,
        accept => 'text/html',
    );
    my $id = expectCookie($res);

    # CIBA request with different login_hint
    my $query = buildForm( {
            client_id     => 'rpid',
            client_secret => 'rpsecret',
            scope         => 'openid',
            login_hint    => 'rtyler',     # Different user
        }
    );

    $res = $op->_post(
        "/oauth2/bc-authorize",
        IO::String->new($query),
        cookie => "lemonldap=$id",
        accept => 'application/json',
        length => length($query),
    );
    ok( $res->[0] == 403, 'Reject: not the same user' );

    # Logout
    $op->_get( '/', cookie => "lemonldap=$id", query => 'logout' );
};

subtest "CIBA ping mode" => sub {
    @ciba_notifications = ();    # Reset notifications
    @ping_notifications = ();    # Reset ping notifications

    my $query = buildForm( {
            client_id                 => 'rpid_ping',
            client_secret             => 'rpsecret_ping',
            scope                     => 'openid profile',
            login_hint                => 'dwho',
            client_notification_token => 'my_token_12345',
        }
    );

    $res = $op->_post(
        "/oauth2/bc-authorize",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    my $payload = expectJSON($res);

    ok( $payload->{auth_req_id}, "Got auth_req_id" );
    my $auth_req_id = $payload->{auth_req_id};

    is( scalar(@ciba_notifications), 1, "Notification sent" );

    my $callback = to_json( {
            auth_req_id => $auth_req_id,
            status      => 'approved',
            sub         => 'dwho',
        }
    );

    $res = $op->_post(
        "/oauth2/ciba-callback",
        IO::String->new($callback),
        accept => 'application/json',
        length => length($callback),
        type   => 'application/json',
        custom => { HTTP_AUTHORIZATION => 'Bearer callback_secret' },
    );
    expectOK($res);

    is( scalar(@ping_notifications), 1, "Ping notification sent to RP" );
    is( $ping_notifications[0]->{auth_req_id},
        $auth_req_id, "Ping contains auth_req_id" );

    $query = buildForm( {
            client_id     => 'rpid_ping',
            client_secret => 'rpsecret_ping',
            grant_type    => 'urn:openid:params:grant-type:ciba',
            auth_req_id   => $auth_req_id,
        }
    );

    $res = $op->_post(
        "/oauth2/token",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    $payload = expectJSON($res);

    ok( $payload->{access_token}, "Got access_token" );
    ok( $payload->{id_token},     "Got id_token" );
};

subtest "CIBA ping mode without token" => sub {
    @ciba_notifications = ();

    my $query = buildForm( {
            client_id     => 'rpid_ping',
            client_secret => 'rpsecret_ping',
            scope         => 'openid',
            login_hint    => 'dwho',

            # Missing client_notification_token
        }
    );

    $res = $op->_post(
        "/oauth2/bc-authorize",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    expectReject( $res, 400, 'invalid_request' );
};

clean_sessions();
done_testing();
