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

LWP::Protocol::PSGI->register(
    sub {
        my $req = Plack::Request->new(@_);
        if ( $req->env->{HTTP_HOST} =~ /^host\.m\.org/ ) {
            if ( $req->path_info eq '/_matrix/federation/v1/openid/userinfo' ) {
                if ( $req->query_string eq 'access_token=bbb' ) {
                    return [
                        200,
                        [],
                        [
                            JSON::to_json( {
                                    sub => '@french:badwolf.org'
                                }
                            )
                        ]
                    ];
                }
                else {
                    return [ 403, [],
                        ['{"errcode": "M_UNAUTHORIZED", "error": "Bad token"}']
                    ];
                }
            }
        }
        if ( $req->env->{HTTP_HOST} =~ /^m\.org/ ) {
            return [
                200,
                [],
                [
                    JSON::to_json( {
                            'm.server' => 'host.m.org:678',
                        }
                    )
                ]
            ];
        }
        print STDERR $req->env->{HTTP_HOST} . "\n";
        return [ 404, [], [] ];
    }
);

sub runTest {
    my ( $op, $jwt ) = @_;
    Time::Fake->reset;

    my $query;
    my $res;

    # Make sure offline session is still valid long after natural session
    # expiration time

    Time::Fake->offset("+10d");

    # Change attribute value
    $Lemonldap::NG::Portal::UserDB::Demo::demoAccounts{french}->{cn} =
      'Frédéric Freedom';

    # Use Matrix token to get an access token
    $query = buildForm( {
            grant_type     => 'urn:ietf:params:oauth:grant-type:token-exchange',
            client_id      => 'rpid',
            subject_token  => 'bbb',
            subject_issuer => 'm.org',
            scope          => 'openid profile email offline_access',
            audience       => 'rpid2',
        }
    );

    ok(
        $res = $op->_post(
            '/oauth2/token', IO::String->new($query),
            accept => 'application/json',
            length => length($query),
            custom =>
              { HTTP_AUTHORIZATION => "Basic " . encode_base64("rpid:rpid"), }
        ),
        'Call /token with Matrix token'
    );

    my $json = expectJSON($res);

    my $access_token = $json->{access_token};
    if ($jwt) {
        expectJWT(
            $access_token,
            name => "Frédéric Freedom",
            sub  => "customfrench"
        );
    }
    my $refresh_token2 = $json->{refresh_token};
    my $id_token       = $json->{id_token};
    ok( $access_token, "Got refreshed Access token" );
    ok( $id_token,     "Got refreshed ID token" );

    my $id_token_payload = id_token_payload($id_token);
    is(
        $id_token_payload->{name},
        'Frédéric Freedom',
        'Found claim in ID token'
    );
    ok( ( grep { $_ eq "rpid2" } @{ $id_token_payload->{aud} } ),
        'Check that clientid is in audience' );

    $json = expectJSON( getUserinfo( $op, $access_token ) );

    is( $json->{name}, "Frédéric Freedom", "Correct user info" );

    ## Test introspection of refreshed token #2171
    $json = expectJSON( introspect( $op, 'rpid', $access_token ) );

    is( $json->{active},    1,       'Token is active' );
    is( $json->{client_id}, 'rpid2', 'Introspection contains client_id' );
    is( $json->{sub},       'customfrench', 'Introspection contains sub' );
}

my $baseConfig = {
    ini => {
        domain                          => 'op.com',
        portal                          => 'http://auth.op.com',
        authentication                  => 'Demo',
        timeoutActivity                 => 3600,
        userDB                          => 'Same',
        customPlugins                   => '::Plugins::MatrixTokenExchange',
        issuerDBOpenIDConnectActivation => 1,
        oidcRPMetaDataExportedVars      => {
            rp => {
                email       => "mail",
                family_name => "cn",
                name        => "cn"
            },
            rp2 => {
                email       => "mail",
                family_name => "cn",
                name        => "cn"
            },
        },
        oidcRPMetaDataMacros => {
            rp => {
                custom_sub => '"custom".$uid',
            },
            rp2 => {
                custom_sub => '"custom".$uid',
            },
        },
        oidcRPMetaDataOptions => {
            rp => {
                oidcRPMetaDataOptionsAccessTokenJWT     => 1,
                oidcRPMetaDataOptionsDisplayName        => "RP",
                oidcRPMetaDataOptionsClientID           => "rpid",
                oidcRPMetaDataOptionsAllowOffline       => 1,
                oidcRPMetaDataOptionsIDTokenSignAlg     => "HS512",
                oidcRPMetaDataOptionsAccessTokenSignAlg => "RS512",
                oidcRPMetaDataOptionsAccessTokenClaims  => 1,
                oidcRPMetaDataOptionsClientSecret       => "rpid",
                oidcRPMetaDataOptionsUserIDAttr         => "custom_sub",
                oidcRPMetaDataOptionsBypassConsent      => 1,
                oidcRPMetaDataOptionsIDTokenForceClaims => 1,
                oidcRPMetaDataOptionsRedirectUris       => 'http://test/',
            },
            rp2 => {
                oidcRPMetaDataOptionsAccessTokenJWT         => 1,
                oidcRPMetaDataOptionsDisplayName            => "RP",
                oidcRPMetaDataOptionsClientID               => "rpid2",
                oidcRPMetaDataOptionsAllowOffline           => 1,
                oidcRPMetaDataOptionsIDTokenSignAlg         => "HS512",
                oidcRPMetaDataOptionsAccessTokenSignAlg     => "RS512",
                oidcRPMetaDataOptionsAccessTokenClaims      => 1,
                oidcRPMetaDataOptionsClientSecret           => "rpid2",
                oidcRPMetaDataOptionsUserIDAttr             => "custom_sub",
                oidcRPMetaDataOptionsBypassConsent          => 1,
                oidcRPMetaDataOptionsIDTokenForceClaims     => 1,
                oidcRPMetaDataOptionsRedirectUris           => 'http://test/',
                oidcRPMetaDataOptionsTokenXAuthorizedMatrix => 'm.org',
            },
        },
        oidcServicePrivateKeySig => oidc_key_op_private_sig,
        oidcServicePublicKeySig  => oidc_cert_op_public_sig,
    }
};

my $op = LLNG::Manager::Test->new($baseConfig);
runTest($op);

clean_sessions();
done_testing();

