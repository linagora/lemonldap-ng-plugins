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

subtest "Authorization code grant: acr + auth_time on JWT access token" => sub {
    my $code = codeAuthorize(
        $op, $idpId,
        {
            response_type => "code",
            scope         => "openid profile",
            client_id     => "rpid",
            state         => "step-up-1",
            redirect_uri  => "http://client.com/",
        }
    );
    my $token_res =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    my $payload = jwt_payload( $token_res->{access_token} );

    is( $payload->{acr}, "loa-1",
        "acr is `loa-<authenticationLevel>` (default mapping)" );
    ok( $payload->{auth_time}, "auth_time is present" );
    cmp_ok( $payload->{auth_time}, '<=', time,
        "auth_time is not in the future" );
};

subtest "AuthnContext mapping: named acr instead of `loa-<n>`" => sub {
    my $op2  = register( 'op_named', sub { op_with_named_acr() } );
    my $id2  = login( $op2, "french" );
    my $code = codeAuthorize(
        $op2, $id2,
        {
            response_type => "code",
            scope         => "openid profile",
            client_id     => "rpid",
            state         => "step-up-2",
            redirect_uri  => "http://client.com/",
        }
    );
    my $token_res =
      expectJSON( codeGrant( $op2, "rpid", $code, "http://client.com/" ) );
    my $payload = jwt_payload( $token_res->{access_token} );

    is( $payload->{acr}, "urn:llng:loa:basic",
        "acr resolves through oidcServiceMetaDataAuthnContext when configured"
    );
};

subtest "Refresh token grant preserves acr + auth_time" => sub {
    my $code = codeAuthorize(
        $op, $idpId,
        {
            response_type => "code",
            scope         => "openid profile offline_access",
            client_id     => "rpid",
            state         => "step-up-rt",
            redirect_uri  => "http://client.com/",
        }
    );
    my $token_res =
      expectJSON( codeGrant( $op, "rpid", $code, "http://client.com/" ) );
    ok( $token_res->{refresh_token}, "Refresh token issued" );
    my $original_at      = jwt_payload( $token_res->{access_token} );
    my $original_authtime = $original_at->{auth_time};

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
    my $new_payload  = jwt_payload( $refresh_json->{access_token} );

    is( $new_payload->{acr}, "loa-1",
        "Refresh-issued AT keeps the original acr" );
    is( $new_payload->{auth_time}, $original_authtime,
        "Refresh-issued AT keeps the original auth_time (not the refresh time)"
    );
};

subtest "Refresh-token rotation preserves acr + auth_time across rotations"
  => sub {
    my $op2 = register( 'op_rotate', sub { op_with_rotation() } );
    my $id2 = login( $op2, "french" );

    my $code = codeAuthorize(
        $op2, $id2,
        {
            response_type => "code",
            scope         => "openid profile offline_access",
            client_id     => "rpid",
            state         => "rotate-1",
            redirect_uri  => "http://client.com/",
        }
    );
    my $first = expectJSON(
        codeGrant( $op2, "rpid", $code, "http://client.com/" ) );
    my $orig_at      = jwt_payload( $first->{access_token} );
    my $orig_atime   = $orig_at->{auth_time};
    my $first_rt     = $first->{refresh_token};
    ok( $first_rt, "First refresh token issued" );
    is( $orig_at->{acr}, "loa-1", "Initial AT carries acr=loa-1" );

    # First rotation: returns a NEW refresh token + a new AT.
    my $second = expectJSON( _refresh( $op2, $first_rt ) );
    ok( $second->{refresh_token}, "Rotation issued a new refresh token" );
    isnt( $second->{refresh_token}, $first_rt,
        "Rotated RT is different from the first" );
    my $second_at = jwt_payload( $second->{access_token} );
    is( $second_at->{acr}, "loa-1",
        "AT after first rotation still carries acr" );
    is( $second_at->{auth_time}, $orig_atime,
        "AT after first rotation still carries the original auth_time" );

    # Second rotation: this is the regression test for storeOnRefreshToken.
    # Without sourcing from $req->data, the new RT issued at the first
    # rotation would have lost the auth context, and this AT would lack
    # the claims.
    my $third = expectJSON( _refresh( $op2, $second->{refresh_token} ) );
    my $third_at = jwt_payload( $third->{access_token} );
    is( $third_at->{acr}, "loa-1",
        "AT after a SECOND rotation still carries acr (regression: PR #20 review)"
    );
    is( $third_at->{auth_time}, $orig_atime,
        "AT after a second rotation still carries the original auth_time" );
};

subtest "Deterministic acr resolution when several names map to one level"
  => sub {
    my $op3 = register( 'op_dup', sub { op_with_duplicate_acr() } );
    my $id3 = login( $op3, "french" );

    # Three names (`urn:llng:loa:aaa/bbb/ccc`) all map to level=1. The
    # documented winner is the alphabetically first one, so `aaa`. Without
    # a sorted-keys lookup, Perl's hash randomization could pick any of
    # the three.
    my $first;
    for ( 1 .. 2 ) {
        my $code = codeAuthorize(
            $op3, $id3,
            {
                response_type => "code",
                scope         => "openid profile",
                client_id     => "rpid",
                state         => "dup-$_",
                redirect_uri  => "http://client.com/",
            }
        );
        my $token_res = expectJSON(
            codeGrant( $op3, "rpid", $code, "http://client.com/" ) );
        my $payload = jwt_payload( $token_res->{access_token} );
        if ( $_ == 1 ) {
            $first = $payload->{acr};
            is( $first, "urn:llng:loa:aaa",
                "alphabetically-first name is chosen (documented winner)" );
        }
        else {
            is( $payload->{acr}, $first,
                "acr is identical across runs (deterministic)" );
        }
    }
};

sub _refresh {
    my ( $op, $rt ) = @_;
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
              . encode_base64( "rpid:rpid", '' ),
        },
    );
}

subtest "RP without StepUpClaims does not get the claims" => sub {
    my $code = codeAuthorize(
        $op, $idpId,
        {
            response_type => "code",
            scope         => "openid profile",
            client_id     => "rpid_off",
            state         => "step-up-off",
            redirect_uri  => "http://client.com/",
        }
    );
    my $token_res =
      expectJSON(
        codeGrant( $op, "rpid_off", $code, "http://client.com/" ) );
    my $payload = jwt_payload( $token_res->{access_token} );

    ok( !defined $payload->{acr},
        "acr absent when RP has not opted in" );
    ok( !defined $payload->{auth_time},
        "auth_time absent when RP has not opted in" );
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
                customPlugins                   => '::Plugins::OIDCStepUp',
                issuerDBOpenIDConnectActivation => "1",
                restSessionServer               => 1,

                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcServiceAllowOffline               => 1,

                oidcRPMetaDataExportedVars => {
                    rp     => { email => "mail", name => "cn" },
                    rp_off => { email => "mail", name => "cn" },
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
                        oidcRPMetaDataOptionsStepUpClaims   => 1,
                    },
                    rp_off => {
                        oidcRPMetaDataOptionsDisplayName           => "RP off",
                        oidcRPMetaDataOptionsClientID              => "rpid_off",
                        oidcRPMetaDataOptionsClientSecret          => "rpid_off",
                        oidcRPMetaDataOptionsIDTokenSignAlg        => "HS512",
                        oidcRPMetaDataOptionsAccessTokenJWT        => 1,
                        oidcRPMetaDataOptionsAccessTokenSignAlg    => "HS512",
                        oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                        oidcRPMetaDataOptionsBypassConsent         => 1,
                        oidcRPMetaDataOptionsRedirectUris   => 'http://client.com/',
                        # opt-out: oidcRPMetaDataOptionsStepUpClaims absent
                    },
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            }
        }
    );
}

sub op_with_named_acr {
    return LLNG::Manager::Test->new( {
            ini => {
                domain                          => 'idp.com',
                portal                          => 'http://auth.op.com/',
                authentication                  => 'Demo',
                userDB                          => 'Same',
                customPlugins                   => '::Plugins::OIDCStepUp',
                issuerDBOpenIDConnectActivation => "1",
                restSessionServer               => 1,

                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcServiceMetaDataAuthnContext       => {
                    'urn:llng:loa:basic'    => 1,
                    'urn:llng:loa:elevated' => 3,
                },

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
                        oidcRPMetaDataOptionsStepUpClaims   => 1,
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
                customPlugins                   => '::Plugins::OIDCStepUp',
                issuerDBOpenIDConnectActivation => "1",
                restSessionServer               => 1,

                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcServiceAllowOffline               => 1,

                oidcRPMetaDataExportedVars =>
                  { rp => { email => "mail", name => "cn" } },
                oidcRPMetaDataOptions => {
                    rp => {
                        oidcRPMetaDataOptionsDisplayName              => "RP",
                        oidcRPMetaDataOptionsClientID                 => "rpid",
                        oidcRPMetaDataOptionsClientSecret             => "rpid",
                        oidcRPMetaDataOptionsIDTokenSignAlg           => "HS512",
                        oidcRPMetaDataOptionsAccessTokenJWT           => 1,
                        oidcRPMetaDataOptionsAccessTokenSignAlg       => "HS512",
                        oidcRPMetaDataOptionsAccessTokenExpiration    => 3600,
                        oidcRPMetaDataOptionsBypassConsent            => 1,
                        oidcRPMetaDataOptionsRedirectUris   => 'http://client.com/',
                        oidcRPMetaDataOptionsAllowOffline             => 1,
                        oidcRPMetaDataOptionsRefreshTokenRotation     => 1,
                        oidcRPMetaDataOptionsStepUpClaims             => 1,
                    },
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            }
        }
    );
}

sub op_with_duplicate_acr {
    return LLNG::Manager::Test->new( {
            ini => {
                domain                          => 'idp.com',
                portal                          => 'http://auth.op.com/',
                authentication                  => 'Demo',
                userDB                          => 'Same',
                customPlugins                   => '::Plugins::OIDCStepUp',
                issuerDBOpenIDConnectActivation => "1",
                restSessionServer               => 1,

                oidcServiceAllowAuthorizationCodeFlow => 1,

                # Two ACR names mapping to the same level. Hash key order
                # would be non-deterministic without a sorted lookup.
                oidcServiceMetaDataAuthnContext => {
                    'urn:llng:loa:bbb' => 1,
                    'urn:llng:loa:aaa' => 1,
                    'urn:llng:loa:ccc' => 1,
                },

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
                        oidcRPMetaDataOptionsStepUpClaims   => 1,
                    },
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            }
        }
    );
}
