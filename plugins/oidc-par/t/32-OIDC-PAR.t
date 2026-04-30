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

my ( $op, $res );

# Initialization
ok( $op = register( 'op', sub { op() } ), 'OP portal' );

my $id = login( $op, "french" );

my %test_authorize_params = (
    response_type => "code",
    scope         => "openid profile",
    state         => "af0ifjsldkj",
    redirect_uri  => "http://rp.com/",
);

# PKCE parameters for later tests
my $code_verifier         = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
my $code_challenge        = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
my $code_challenge_method = "S256";

subtest "PAR endpoint is advertised in metadata" => sub {
    my $res = $op->_get(
        "/.well-known/openid-configuration",
        accept => 'application/json',
    );
    my $json = expectJSON($res);
    ok( $json->{pushed_authorization_request_endpoint},
        "PAR endpoint is present in metadata" );
    like(
        $json->{pushed_authorization_request_endpoint},
        qr/\/par$/,
        "PAR endpoint URL is correct"
    );
};

subtest "Basic PAR flow works" => sub {

    # Step 1: Push authorization request
    my $par_res = parRequest(
        $op, "rp",
        {
            %test_authorize_params,
            client_id => "rp",
        }
    );
    is( $par_res->[0], 201, "PAR request returns 201 Created" );
    my $par_json = parJSON($par_res);
    ok( $par_json->{request_uri}, "request_uri is returned" );
    like(
        $par_json->{request_uri},
        qr/^urn:ietf:params:oauth:request_uri:/,
        "request_uri has correct format"
    );
    ok( $par_json->{expires_in}, "expires_in is returned" );

    # Step 2: Use request_uri in authorize endpoint
    my $auth_res = authorize(
        $op, $id,
        {
            client_id   => "rp",
            request_uri => $par_json->{request_uri},
        }
    );

    my ($code) = expectRedirection( $auth_res, qr#http://.*code=([^\&]*)# );
    ok( $code, "Authorization code received" );

    # Step 3: Exchange code for tokens
    my $token_res = expectJSON(
        codeGrant( $op, "rp", $code, "http://rp.com/" )
    );
    ok( $token_res->{access_token}, "Access token received" );
};

subtest "PAR with PKCE works" => sub {

    # Step 1: Push authorization request with PKCE
    my $par_res = parRequest(
        $op, "rp",
        {
            %test_authorize_params,
            client_id             => "rp",
            code_challenge        => $code_challenge,
            code_challenge_method => $code_challenge_method,
        }
    );
    is( $par_res->[0], 201, "PAR request returns 201 Created" );
    my $par_json = parJSON($par_res);

    # Step 2: Use request_uri in authorize endpoint
    my $auth_res = authorize(
        $op, $id,
        {
            client_id   => "rp",
            request_uri => $par_json->{request_uri},
        }
    );

    my ($code) = expectRedirection( $auth_res, qr#http://.*code=([^\&]*)# );
    ok( $code, "Authorization code received" );

    # Step 3: Exchange code for tokens with code_verifier
    my $token_res = expectJSON(
        codeGrant( $op, "rp", $code, "http://rp.com/",
            code_verifier => $code_verifier )
    );
    ok( $token_res->{access_token}, "Access token received with PKCE" );
};

subtest "PAR request_uri is one-time use" => sub {

    # Push authorization request
    my $par_res = parRequest(
        $op, "rp",
        {
            %test_authorize_params,
            client_id => "rp",
        }
    );
    my $par_json = parJSON($par_res);

    # First use should succeed
    my $auth_res1 = authorize(
        $op, $id,
        {
            client_id   => "rp",
            request_uri => $par_json->{request_uri},
        }
    );
    expectRedirection( $auth_res1, qr#http://.*code=# );

    # Second use should fail
    my $auth_res2 = authorize(
        $op, $id,
        {
            client_id   => "rp",
            request_uri => $par_json->{request_uri},
        }
    );

    # Should get error - the request_uri is consumed
    expectPortalError( $auth_res2, 24, "request_uri reuse fails" );
};

subtest "PAR client_id mismatch fails" => sub {

    # Push authorization request for rp
    my $par_res = parRequest(
        $op, "rp",
        {
            %test_authorize_params,
            client_id => "rp",
        }
    );
    my $par_json = parJSON($par_res);

    # Try to use with different client_id
    my $auth_res = authorize(
        $op, $id,
        {
            client_id   => "rp2",    # Different from PAR
            request_uri => $par_json->{request_uri},
        }
    );

    expectPortalError( $auth_res, 24, "client_id mismatch fails" );
};

subtest "PAR with invalid redirect_uri fails" => sub {
    my $par_res = parRequest(
        $op, "rp",
        {
            %test_authorize_params,
            client_id    => "rp",
            redirect_uri => "http://invalid.com/",
        }
    );
    is( $par_res->[0], 400, "PAR request returns 400 Bad Request" );
    my $par_json = parJSON($par_res);
    is( $par_json->{error}, "invalid_request", "Error is invalid_request" );
};

subtest "PAR without client authentication fails" => sub {
    my $query = buildForm(
        {
            %test_authorize_params,
            client_id => "rp",
        }
    );

    my $res = $op->_post(
        "/oauth2/par",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),

        # No authorization header
    );
    is( $res->[0], 401, "PAR request returns 401 Unauthorized" );
    my $json = parJSON($res);
    is( $json->{error}, "invalid_client", "Error is invalid_client" );
};

subtest "PAR required for RP" => sub {

    # Direct authorize without PAR should fail (returns PE_ERROR as error page)
    my $auth_res = authorize(
        $op, $id,
        {
            %test_authorize_params,
            client_id => "rp_par",
        }
    );

    # When PAR is required but not used, we get a portal error page
    expectPortalError( $auth_res, 24, "Authorize without PAR fails for RP requiring PAR" );

    # PAR flow should succeed
    my $par_res = parRequest(
        $op, "rp_par",
        {
            %test_authorize_params,
            client_id => "rp_par",
        }
    );
    is( $par_res->[0], 201, "PAR request succeeds" );
    my $par_json = parJSON($par_res);

    my $auth_res2 = authorize(
        $op, $id,
        {
            client_id   => "rp_par",
            request_uri => $par_json->{request_uri},
        }
    );

    my ($code) = expectRedirection( $auth_res2, qr#http://.*code=([^\&]*)# );
    ok( $code, "Authorization code received with PAR" );
};

subtest "Normal authorize works when PAR is allowed but not required" => sub {

    # Direct authorize without PAR should work for RP with PAR='allowed'
    my $auth_res = authorize(
        $op, $id,
        {
            %test_authorize_params,
            client_id => "rp",
        }
    );

    my ($code) = expectRedirection( $auth_res, qr#http://.*code=([^\&]*)# );
    ok( $code, "Authorization code received without PAR" );

    # Exchange code for tokens
    my $token_res = expectJSON(
        codeGrant( $op, "rp", $code, "http://rp.com/" )
    );
    ok( $token_res->{access_token}, "Access token received without PAR" );
};

subtest "PAR disabled for RP fails" => sub {
    my $par_res = parRequest(
        $op, "rp_nopar",
        {
            %test_authorize_params,
            client_id => "rp_nopar",
        }
    );
    is( $par_res->[0], 400, "PAR request returns 400 for disabled RP" );
    my $par_json = parJSON($par_res);
    is( $par_json->{error}, "invalid_request", "Error is invalid_request" );
};

subtest "PAR missing required parameters fails" => sub {

    # Missing redirect_uri
    my $par_res1 = parRequest(
        $op, "rp",
        {
            response_type => "code",
            scope         => "openid",
            client_id     => "rp",

            # No redirect_uri
        }
    );
    is( $par_res1->[0], 400, "PAR without redirect_uri returns 400" );
    my $json1 = parJSON($par_res1);
    is( $json1->{error}, "invalid_request", "Error is invalid_request" );

    # Missing response_type
    my $par_res2 = parRequest(
        $op, "rp",
        {
            scope        => "openid",
            client_id    => "rp",
            redirect_uri => "http://rp.com/",

            # No response_type
        }
    );
    is( $par_res2->[0], 400, "PAR without response_type returns 400" );
    my $json2 = parJSON($par_res2);
    is( $json2->{error}, "invalid_request", "Error is invalid_request" );
};

subtest "PAR accepts the authorization_details parameter (RFC 9396)" => sub {

    # Verifies that the push side does not reject `authorization_details` as
    # an unknown parameter. End-to-end semantics (the parameter actually
    # surfaces in the token response) require oidc-rar to be active, and
    # are covered by the corresponding subtest in oidc-rar's test suite.
    my $details = '[{"type":"payment_initiation","amount":"42"}]';
    my $par_res = parRequest(
        $op, "rp",
        {
            %test_authorize_params,
            client_id             => "rp",
            authorization_details => $details,
        }
    );
    is( $par_res->[0], 201, "PAR with authorization_details returns 201" );
    my $par_json = parJSON($par_res);
    ok( $par_json->{request_uri},
        "request_uri returned for RAR-carrying PAR" );
};

clean_sessions();
done_testing();

# Client-side PAR tests are in t/32-OIDC-PAR-client.t

sub parRequest {
    local $Test::Builder::Level = $Test::Builder::Level + 1;
    my ( $op, $clientid, $params ) = @_;

    my $query = buildForm($params);

    my $res = $op->_post(
        "/oauth2/par",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
        custom => {
            HTTP_AUTHORIZATION => "Basic "
              . encode_base64( "$clientid:$clientid", '' ),
        },
    );
    return $res;
}

# Helper to parse PAR JSON response (doesn't check HTTP 200)
sub parJSON {
    my $res = shift;
    return from_json( $res->[2]->[0] );
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
                    rp2 => {
                        email  => "mail",
                        name   => "cn",
                        groups => "groups",
                    },
                    rp_par => {
                        email  => "mail",
                        name   => "cn",
                        groups => "groups",
                    },
                    rp_nopar => {
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
                        oidcRPMetaDataOptionsRedirectUris          => 'http://rp.com/',
                        oidcRPMetaDataOptionsPAR                   => 'allowed',
                    },
                    rp2 => {
                        oidcRPMetaDataOptionsDisplayName           => "RP2",
                        oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                        oidcRPMetaDataOptionsClientID              => "rp2",
                        oidcRPMetaDataOptionsIDTokenSignAlg        => "RS256",
                        oidcRPMetaDataOptionsBypassConsent         => 1,
                        oidcRPMetaDataOptionsClientSecret          => "rp2",
                        oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                        oidcRPMetaDataOptionsRedirectUris          => 'http://rp.com/',
                        oidcRPMetaDataOptionsPAR                   => 'allowed',
                    },
                    rp_par => {
                        oidcRPMetaDataOptionsDisplayName           => "RP PAR",
                        oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                        oidcRPMetaDataOptionsClientID              => "rp_par",
                        oidcRPMetaDataOptionsIDTokenSignAlg        => "RS256",
                        oidcRPMetaDataOptionsBypassConsent         => 1,
                        oidcRPMetaDataOptionsClientSecret          => "rp_par",
                        oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                        oidcRPMetaDataOptionsRedirectUris          => 'http://rp.com/',
                        oidcRPMetaDataOptionsPAR                   => 'required',
                    },
                    rp_nopar => {
                        oidcRPMetaDataOptionsDisplayName           => "RP No PAR",
                        oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                        oidcRPMetaDataOptionsClientID              => "rp_nopar",
                        oidcRPMetaDataOptionsIDTokenSignAlg        => "RS256",
                        oidcRPMetaDataOptionsBypassConsent         => 1,
                        oidcRPMetaDataOptionsClientSecret          => "rp_nopar",
                        oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                        oidcRPMetaDataOptionsRedirectUris          => 'http://rp.com/',
                        # PAR disabled (default)
                    },
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            }
        }
    );
}
