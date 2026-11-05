use warnings;
use strict;
use Test::More;
use IO::String;
use LWP::UserAgent;
use LWP::Protocol::PSGI;
use JSON qw(from_json);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my @notifications;

LWP::Protocol::PSGI->register(
    sub {
        my $req = Plack::Request->new(@_);
        if ( $req->uri =~ m#^http://ciba-channel/notify# ) {
            push @notifications, from_json( $req->content );
            return [ 200, [ 'Content-Type' => 'application/json' ], ['{}'] ];
        }
        return [ 404, [], ['Not found'] ];
    }
);

my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                           => 'error',
            domain                             => 'op.com',
            portal                             => 'http://auth.op.com/',
            authentication                     => 'Choice',
            authChoiceParam                    => 'test',
            authChoiceModules                  => { demo => 'Demo;Demo;Demo' },
            userDB                             => 'Same',
            customPlugins                      => '::Plugins::OIDCCIBA',
            issuerDBOpenIDConnectActivation    => 1,
            oidcServiceCibaChoice              => 'demo',
            oidcServiceMetaDataCibaURI         => 'bc-authorize',
            oidcServiceMetaDataCibaCallbackURI => 'ciba-callback',
            oidcServiceCibaAuthenticationChannelUrl =>
              'http://ciba-channel/notify',
            oidcServiceCibaCallbackSecret => 'callback_secret',
            oidcRPMetaDataOptions         => {
                rp => {
                    oidcRPMetaDataOptionsDisplayName           => 'RP',
                    oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                    oidcRPMetaDataOptionsIDTokenSignAlg        => 'RS256',
                    oidcRPMetaDataOptionsClientID              => 'rpid',
                    oidcRPMetaDataOptionsClientSecret          => 'rpsecret',
                    oidcRPMetaDataOptionsUserIDAttr            => '',
                    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                    oidcRPMetaDataOptionsBypassConsent         => 1,
                    oidcRPMetaDataOptionsAllowCIBA             => 1,
                    oidcRPMetaDataOptionsCIBAMode              => 'poll',
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig(),
            oidcServicePublicKeySig  => oidc_cert_op_public_sig(),
        }
    }
);

my $query = buildForm( {
        client_id     => 'rpid',
        client_secret => 'rpsecret',
        scope         => 'openid',
        login_hint    => 'dwho',
    }
);
my $res = $op->_post(
    '/oauth2/bc-authorize',
    IO::String->new($query),
    accept => 'application/json',
    length => length($query),
);
my $payload = expectJSON($res);
ok( $payload->{auth_req_id}, 'user resolved with authentication = Choice' );
is( scalar @notifications, 1, 'the authentication channel is called' );

clean_sessions();
done_testing();
