use warnings;
use strict;
use Test::More;
use IO::String;
use JSON;
use MIME::Base64;
use Lemonldap::NG::Common::JWT qw(getJWTPayload);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

# A scope added to the browser URL must not bring back "applications" when
# the pushed request does not ask for it.
my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                         => 'error',
            domain                           => 'idp.com',
            portal                           => 'http://auth.op.com/',
            authentication                   => 'Demo',
            userDB                           => 'Same',
            issuerDBOpenIDConnectActivation  => 1,
            oidcServiceMetaDataPushedAuthURI => 'par',
            customPlugins =>
              '::Plugins::OIDCScopeApplications, ::Plugins::OIDCPushedAuthRequest',
            oidcRPMetaDataExportedVars => { rp => { email => 'mail' } },
            oidcRPMetaDataOptions      => {
                rp => {
                    oidcRPMetaDataOptionsDisplayName           => 'RP',
                    oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                    oidcRPMetaDataOptionsClientID              => 'rp',
                    oidcRPMetaDataOptionsIDTokenSignAlg        => 'RS256',
                    oidcRPMetaDataOptionsClientSecret          => 'rp',
                    oidcRPMetaDataOptionsUserIDAttr            => '',
                    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                    oidcRPMetaDataOptionsAccessTokenJWT        => 1,
                    oidcRPMetaDataOptionsBypassConsent         => 1,
                    oidcRPMetaDataOptionsPAR                   => 'allowed',
                    oidcRPMetaDataOptionsAllowScopeApplications => 1,
                    oidcRPMetaDataOptionsRedirectUris => 'http://rp.com/',
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig(),
            oidcServicePublicKeySig  => oidc_cert_op_public_sig(),
        }
    }
);

my $id   = login( $op, 'dwho' );
my $body = 'response_type=code&client_id=rp&state=s&nonce=n&scope=openid'
  . '&redirect_uri=http%3A%2F%2Frp.com%2F';
my $par_res = $op->_post(
    '/oauth2/par', IO::String->new($body),
    accept => 'application/json',
    length => length($body),
    custom => { HTTP_AUTHORIZATION => 'Basic ' . encode_base64( 'rp:rp', '' ) },
);
is( $par_res->[0], 201, 'PAR request accepted' );
my $par = from_json( $par_res->[2]->[0] );

my $code = codeAuthorize(
    $op, $id,
    {
        client_id   => 'rp',
        request_uri => $par->{request_uri},
        scope       => 'openid applications',
    }
);
my $json  = expectJSON( codeGrant( $op, 'rp', $code, 'http://rp.com/' ) );
my %scope = map { $_ => 1 } split /\s+/,
  getJWTPayload( $json->{access_token} )->{scope};
ok( !$scope{applications},
    'the browser does not add applications to the pushed scope' );
ok( $scope{openid}, 'the pushed scope is granted' );

clean_sessions();
done_testing();
