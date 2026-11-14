use warnings;
use Test::More;
use strict;
use IO::String;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

# RFC 8252 section 7.3: a declared loopback redirect URI accepts any port

# Example from RFC 7636 appendix B
my $code_verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
my $code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

sub rp {
    my ( $id, $uris ) = @_;
    return {
        oidcRPMetaDataOptionsDisplayName           => $id,
        oidcRPMetaDataOptionsClientID              => $id,
        oidcRPMetaDataOptionsIDTokenSignAlg        => "RS256",
        oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
        oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
        oidcRPMetaDataOptionsBypassConsent         => 1,
        oidcRPMetaDataOptionsPublic                => 1,
        oidcRPMetaDataOptionsRequirePKCE           => 1,
        oidcRPMetaDataOptionsRedirectUris          => $uris,
    };
}

sub new_op {
    my (%extra) = @_;
    return LLNG::Manager::Test->new( {
            ini => {
                domain                                => 'op.com',
                portal                                => 'http://auth.op.com/',
                authentication                        => 'Demo',
                userDB                                => 'Same',
                issuerDBOpenIDConnectActivation       => 1,
                oidcServiceMetaDataIssuer             => 'http://auth.op.com',
                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcServicePrivateKeySig => oidc_key_op_private_sig(),
                oidcServicePublicKeySig  => oidc_cert_op_public_sig(),
                customPlugins => 'Lemonldap::NG::Portal::Plugins::PACC',
                paccEnabled   => 1,
                oidcRPMetaDataExportedVars => {
                    mailcraft => { email => "mail" },
                    webapp    => { email => "mail" },
                },
                oidcRPMetaDataOptions => {
                    mailcraft => rp(
                        mailcraft => 'http://127.0.0.1/ http://[::1]/cb?x=1'
                    ),
                    webapp => rp( webapp => 'http://rp.com/' ),
                },
                %extra,
            }
        }
    );
}

sub try_authorize {
    my ( $op, $id, $client_id, $redirect_uri ) = @_;
    return authorize(
        $op, $id,
        {
            response_type         => 'code',
            scope                 => 'openid',
            state                 => 'xyz',
            client_id             => $client_id,
            redirect_uri          => $redirect_uri,
            code_challenge        => $code_challenge,
            code_challenge_method => 'S256',
        }
    );
}

# Returns the code when the OP redirected to $redirect_uri, undef otherwise
sub code_for {
    my ( $op, $id, $client_id, $redirect_uri ) = @_;
    my $res      = try_authorize( $op, $id, $client_id, $redirect_uri );
    my $location = getHeader( $res, 'Location' ) // '';
    return undef unless $res->[0] == 302;
    return undef unless index( $location, $redirect_uri ) == 0;
    my ($code) = $location =~ /[?&]code=([^&]+)/;
    return $code;
}

my $op = new_op();
my $id = login( $op, 'french' );

subtest 'any port is accepted on a declared loopback URI' => sub {
    for my $uri (
        'http://127.0.0.1:56170/', 'http://127.0.0.1:1/',
        'http://127.0.0.1:65535/', 'http://127.0.0.1/',
        'http://127.0.0.1:8080',   'http://[::1]:4000/cb?x=1',
      )
    {
        ok( code_for( $op, $id, 'mailcraft', $uri ), "accepted: $uri" );
    }
};

subtest 'only the port may differ' => sub {
    for my $uri (
        'http://127.0.0.1:56170/other',        # path
        'http://127.0.0.1:56170/?x=1',         # query
        'http://localhost:56170/',             # host switch
        'http://[::1]:56170/',                 # host switch
        'http://[::1]:4000/cb',                # query dropped
        'https://127.0.0.1:56170/',            # scheme
        'http://127.0.0.1:0/',                 # invalid port
        'http://127.0.0.1:70000/',             # invalid port
        'http://127.0.0.1:/',                  # empty port
        'http://127.0.0.1:56170@evil.com/',    # userinfo trick
        'http://127.0.0.1.evil.com:56170/',    # not a loopback host
      )
    {
        ok( !code_for( $op, $id, 'mailcraft', $uri ), "refused: $uri" );
    }
};

subtest 'RP without loopback URI is not affected' => sub {
    ok( code_for( $op,  $id, 'webapp', 'http://rp.com/' ), 'exact URI works' );
    ok( !code_for( $op, $id, 'webapp', 'http://rp.com:8080/' ),
        'other port refused' );
    ok(
        !code_for( $op, $id, 'webapp', 'http://127.0.0.1:8080/' ),
        'loopback URI not declared for this RP is refused'
    );
};

subtest 'token exchange with a random port' => sub {
    my $uri  = 'http://127.0.0.1:56170/';
    my $code = code_for( $op, $id, 'mailcraft', $uri );
    ok( $code, 'got a code' );
    my $json = expectJSON(
        codeGrantNoSecret(
            $op, 'mailcraft', $code, $uri, code_verifier => $code_verifier
        )
    );
    ok( $json->{access_token}, 'access token issued' );

    # The token endpoint keeps comparing with the authorization request
    $code = code_for( $op, $id, 'mailcraft', $uri );
    expectReject(
        codeGrantNoSecret(
            $op, 'mailcraft', $code, 'http://127.0.0.1:56171/',
            code_verifier => $code_verifier
        ),
        400,
        'invalid_grant'
    );
};

subtest 'option disabled' => sub {
    my $op_off = new_op( paccLoopbackAnyPort => 0 );
    my $id_off = login( $op_off, 'french' );
    ok( code_for( $op_off, $id_off, 'mailcraft', 'http://127.0.0.1/' ),
        'exact loopback URI still works' );
    ok( !code_for( $op_off, $id_off, 'mailcraft', 'http://127.0.0.1:56170/' ),
        'other port refused' );
};

clean_sessions();
done_testing();
