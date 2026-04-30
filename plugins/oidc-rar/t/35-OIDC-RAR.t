use warnings;
use Test::More;
use strict;
use IO::String;
use MIME::Base64 qw/encode_base64/;
use JSON;
use Lemonldap::NG::Portal::Main::Request;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my ( $op, $res );

ok( $op = register( 'op', sub { op() } ), 'OP portal' );

my $id = login( $op, "french" );

my %base_authorize = (
    response_type => "code",
    scope         => "openid profile",
    state         => "af0ifjsldkj",
    redirect_uri  => "http://rp.com/",
);

my $valid_details = encode_json( [ {
        type             => "payment_initiation",
        instructedAmount => { currency => "EUR", amount => "100.00" },
} ] );

subtest "Discovery advertises authorization_details_types_supported" => sub {
    my $res = $op->_get(
        "/.well-known/openid-configuration",
        accept => 'application/json',
    );
    my $json = expectJSON($res);
    ok( $json->{authorization_details_types_supported},
        "authorization_details_types_supported is present" );
    is_deeply(
        [ sort @{ $json->{authorization_details_types_supported} } ],
        [ "account_information", "payment_initiation" ],
        "supported types are correct"
    );
};

subtest "Valid authorization_details echoed in token response" => sub {
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp",
            authorization_details => $valid_details,
        }
    );
    my ($code) = expectRedirection( $auth_res, qr#http://.*code=([^\&]*)# );
    ok( $code, "Authorization code received" );

    my $token_res = expectJSON(
        codeGrant( $op, "rp", $code, "http://rp.com/" )
    );
    ok( $token_res->{authorization_details},
        "authorization_details echoed in token response" );
    is( $token_res->{authorization_details}->[0]->{type},
        "payment_initiation", "echoed type matches" );
    is( $token_res->{authorization_details}->[0]->{instructedAmount}
          ->{amount},
        "100.00", "echoed payload matches" );
};

subtest "JWT access token carries authorization_details claim" => sub {
    my $code = codeAuthorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp",
            authorization_details => $valid_details,
        }
    );
    my $token_res = expectJSON(
        codeGrant( $op, "rp", $code, "http://rp.com/" )
    );
    my $payload = getJWTPayload( $token_res->{access_token} );
    ok( $payload, "Access token is a JWT" );
    ok( $payload->{authorization_details},
        "authorization_details claim present in JWT" );
    is( $payload->{authorization_details}->[0]->{type},
        "payment_initiation", "claim type matches" );
};

subtest "Introspection includes authorization_details" => sub {
    my $code = codeAuthorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp",
            authorization_details => $valid_details,
        }
    );
    my $token_res = expectJSON(
        codeGrant( $op, "rp", $code, "http://rp.com/" )
    );
    my $intro = expectJSON(
        introspect( $op, "rp", $token_res->{access_token} ) );
    ok( $intro->{authorization_details},
        "authorization_details present in introspection" );
    is( $intro->{authorization_details}->[0]->{type},
        "payment_initiation", "introspected type matches" );
};

subtest "Refresh token preserves authorization_details" => sub {
    my $code = codeAuthorize(
        $op, $id,
        {
            %base_authorize,
            scope                 => "openid profile offline_access",
            client_id             => "rp",
            authorization_details => $valid_details,
        }
    );
    my $token_res = expectJSON(
        codeGrant( $op, "rp", $code, "http://rp.com/" )
    );
    ok( $token_res->{refresh_token}, "refresh_token issued" );

    my $query = buildForm( {
            grant_type    => "refresh_token",
            refresh_token => $token_res->{refresh_token},
    } );
    my $refresh_res = $op->_post(
        "/oauth2/token",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
        custom => {
            HTTP_AUTHORIZATION => "Basic " . encode_base64( "rp:rp", '' ),
        },
    );
    my $refresh_json = expectJSON($refresh_res);
    ok( $refresh_json->{authorization_details},
        "refresh response includes authorization_details" );
    is( $refresh_json->{authorization_details}->[0]->{type},
        "payment_initiation", "refresh keeps original type" );
};

subtest "Type not in allowlist is rejected" => sub {
    my $bad = encode_json( [ { type => "ride_hailing" } ] );
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp",
            authorization_details => $bad,
        }
    );
    expectPortalError( $auth_res, 24,
        "type outside allowlist returns portal error" );
};

subtest "Malformed JSON is rejected" => sub {
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp",
            authorization_details => "not_json{",
        }
    );
    expectPortalError( $auth_res, 24,
        "malformed JSON returns portal error" );
};

subtest "Detail missing `type` is rejected" => sub {
    my $bad = encode_json( [ { foo => "bar" } ] );
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp",
            authorization_details => $bad,
        }
    );
    expectPortalError( $auth_res, 24,
        "detail without `type` returns portal error" );
};

subtest "Perl rule rejects detail when condition fails" => sub {
    # rp_strict has a rule requiring detail->{instructedAmount}{amount} <= 50
    my $over = encode_json( [ {
            type             => "payment_initiation",
            instructedAmount => { currency => "EUR", amount => "9999.00" },
    } ] );
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp_strict",
            authorization_details => $over,
        }
    );
    expectPortalError( $auth_res, 24,
        "rule rejection returns portal error" );
};

subtest "Perl rule grants detail when condition holds" => sub {
    my $ok_detail = encode_json( [ {
            type             => "payment_initiation",
            instructedAmount => { currency => "EUR", amount => "10.00" },
    } ] );
    my $code = codeAuthorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp_strict",
            authorization_details => $ok_detail,
        }
    );
    my $token_res = expectJSON(
        codeGrant( $op, "rp_strict", $code, "http://rp.com/" )
    );
    ok( $token_res->{authorization_details},
        "small payment is granted by rule" );
};

subtest "Uncompilable Perl rule fails closed (deny-all)" => sub {
    # rp_badrule has a syntactically broken rule; the plugin must install a
    # deny-all fallback rather than silently dropping the rule (which would
    # weaken authorization).
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp_badrule",
            authorization_details => $valid_details,
        }
    );
    expectPortalError( $auth_res, 24,
        "broken rule denies all RAR requests for the RP" );
};

subtest "RP without RAR enabled rejects authorization_details" => sub {
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp_norar",
            authorization_details => $valid_details,
        }
    );
    expectPortalError( $auth_res, 24,
        "RAR-disabled RP returns portal error when details are sent" );
};

subtest "Consent template variable is HTML-escaped (XSS prevention)" => sub {
    my $plugin = $op->p->loadedModules->{
        'Lemonldap::NG::Portal::Plugins::OIDCRichAuthRequest' };
    ok( $plugin, "RAR plugin is loaded" );

    my $req = Lemonldap::NG::Portal::Main::Request->new( {} );
    $req->data->{_rar_details} = [ {
            type => "payment_initiation",
            note => '<script>alert(1)</script>',
            html => '<img src=x onerror="alert(2)">',
    } ];
    my $tpl  = "oidcGiveConsent";
    my $args = { params => {} };

    $plugin->injectConsentDetails( $req, \$tpl, $args );
    my $out = $args->{params}->{RAR_DETAILS};
    ok( $out, "RAR_DETAILS variable is set" );
    unlike( $out, qr/<script>/,
        "raw <script> tag is not present in the rendered variable" );
    unlike( $out, qr/<img/,
        "raw <img> tag is not present in the rendered variable" );
    like( $out, qr/&lt;script&gt;/, "<script> is HTML-encoded" );
    like( $out, qr/&quot;/,        '" is HTML-encoded' );
};

subtest "Consent injection skips non-consent OIDC templates" => sub {
    my $plugin = $op->p->loadedModules->{
        'Lemonldap::NG::Portal::Plugins::OIDCRichAuthRequest' };
    my $req = Lemonldap::NG::Portal::Main::Request->new( {} );
    $req->data->{_rar_details} = [ { type => "payment_initiation" } ];

    for my $tpl_name (qw/oidcLogout oidcOfflineTokens login/) {
        my $tpl  = $tpl_name;
        my $args = { params => {} };
        $plugin->injectConsentDetails( $req, \$tpl, $args );
        ok( !exists $args->{params}->{RAR_DETAILS},
            "$tpl_name template is left alone" );
    }
};

subtest "Request without authorization_details still works" => sub {
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id => "rp",
        }
    );
    my ($code) = expectRedirection( $auth_res, qr#http://.*code=([^\&]*)# );
    ok( $code, "Authorization code received without RAR" );

    my $token_res = expectJSON(
        codeGrant( $op, "rp", $code, "http://rp.com/" )
    );
    ok( $token_res->{access_token}, "Access token received" );
    ok( !$token_res->{authorization_details},
        "no authorization_details in response when not requested" );
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
                customPlugins                   => '::Plugins::OIDCRichAuthRequest',
                issuerDBOpenIDConnectActivation => "1",
                restSessionServer               => 1,

                # RAR global allowlist
                oidcServiceAuthorizationDetailsTypes =>
                  'payment_initiation,account_information',

                oidcRPMetaDataExportedVars => {
                    rp         => { email => "mail", name => "cn", groups => "groups" },
                    rp_strict  => { email => "mail", name => "cn", groups => "groups" },
                    rp_norar   => { email => "mail", name => "cn", groups => "groups" },
                    rp_badrule => { email => "mail", name => "cn", groups => "groups" },
                },
                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcServiceAllowOffline               => 1,
                oidcRPMetaDataOptions                 => {
                    rp => {
                        oidcRPMetaDataOptionsDisplayName            => "RP",
                        oidcRPMetaDataOptionsIDTokenExpiration      => 3600,
                        oidcRPMetaDataOptionsClientID               => "rp",
                        oidcRPMetaDataOptionsClientSecret           => "rp",
                        oidcRPMetaDataOptionsIDTokenSignAlg         => "RS256",
                        oidcRPMetaDataOptionsBypassConsent          => 1,
                        oidcRPMetaDataOptionsAccessTokenExpiration  => 3600,
                        oidcRPMetaDataOptionsAccessTokenJWT         => 1,
                        oidcRPMetaDataOptionsAccessTokenSignAlg     => "RS256",
                        oidcRPMetaDataOptionsRedirectUris           => 'http://rp.com/',
                        oidcRPMetaDataOptionsAllowOffline           => 1,
                        oidcRPMetaDataOptionsAuthorizationDetailsEnabled => 1,
                        oidcRPMetaDataOptionsAuthorizationDetailsTypes =>
                          'payment_initiation,account_information',
                    },
                    rp_strict => {
                        oidcRPMetaDataOptionsDisplayName            => "RP Strict",
                        oidcRPMetaDataOptionsIDTokenExpiration      => 3600,
                        oidcRPMetaDataOptionsClientID               => "rp_strict",
                        oidcRPMetaDataOptionsClientSecret           => "rp_strict",
                        oidcRPMetaDataOptionsIDTokenSignAlg         => "RS256",
                        oidcRPMetaDataOptionsBypassConsent          => 1,
                        oidcRPMetaDataOptionsAccessTokenExpiration  => 3600,
                        oidcRPMetaDataOptionsRedirectUris           => 'http://rp.com/',
                        oidcRPMetaDataOptionsAuthorizationDetailsEnabled => 1,
                        oidcRPMetaDataOptionsAuthorizationDetailsTypes =>
                          'payment_initiation',
                        # Rule: only allow payments up to 50 EUR
                        oidcRPMetaDataOptionsAuthorizationDetailsRule =>
                          '$type ne "payment_initiation" or $detail->{instructedAmount}->{amount} <= 50',
                    },
                    rp_norar => {
                        oidcRPMetaDataOptionsDisplayName            => "RP NoRAR",
                        oidcRPMetaDataOptionsIDTokenExpiration      => 3600,
                        oidcRPMetaDataOptionsClientID               => "rp_norar",
                        oidcRPMetaDataOptionsClientSecret           => "rp_norar",
                        oidcRPMetaDataOptionsIDTokenSignAlg         => "RS256",
                        oidcRPMetaDataOptionsBypassConsent          => 1,
                        oidcRPMetaDataOptionsAccessTokenExpiration  => 3600,
                        oidcRPMetaDataOptionsRedirectUris           => 'http://rp.com/',
                        # RAR disabled
                    },
                    rp_badrule => {
                        oidcRPMetaDataOptionsDisplayName            => "RP BadRule",
                        oidcRPMetaDataOptionsIDTokenExpiration      => 3600,
                        oidcRPMetaDataOptionsClientID               => "rp_badrule",
                        oidcRPMetaDataOptionsClientSecret           => "rp_badrule",
                        oidcRPMetaDataOptionsIDTokenSignAlg         => "RS256",
                        oidcRPMetaDataOptionsBypassConsent          => 1,
                        oidcRPMetaDataOptionsAccessTokenExpiration  => 3600,
                        oidcRPMetaDataOptionsRedirectUris           => 'http://rp.com/',
                        oidcRPMetaDataOptionsAuthorizationDetailsEnabled => 1,
                        # Syntactically broken Perl: must trigger fail-closed
                        oidcRPMetaDataOptionsAuthorizationDetailsRule =>
                          'this is not valid perl ((',
                    },
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            }
        }
    );
}
