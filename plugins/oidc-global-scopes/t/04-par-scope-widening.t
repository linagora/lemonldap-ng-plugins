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

# A scope added to the browser URL must not come back through a global scope
# when the pushed request does not ask for it.
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
              '::Plugins::OIDCGlobalScopes, ::Plugins::OIDCPushedAuthRequest',
            oidcServiceGlobalExtraScopes => { corporate => 'department' },
            oidcRPMetaDataExportedVars   => { rp => { email => 'mail' } },
            oidcRPMetaDataOptions        => {
                rp => {
                    oidcRPMetaDataOptionsDisplayName           => 'RP',
                    oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                    oidcRPMetaDataOptionsClientID              => 'rpid',
                    oidcRPMetaDataOptionsIDTokenSignAlg        => 'RS256',
                    oidcRPMetaDataOptionsClientSecret          => 'rpid',
                    oidcRPMetaDataOptionsUserIDAttr            => '',
                    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                    oidcRPMetaDataOptionsAccessTokenJWT        => 1,
                    oidcRPMetaDataOptionsBypassConsent         => 1,
                    oidcRPMetaDataOptionsPAR                   => 'allowed',
                    oidcRPMetaDataOptionsRedirectUris => 'http://rp.com/',
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig(),
            oidcServicePublicKeySig  => oidc_cert_op_public_sig(),
        }
    }
);

my $id   = login( $op, 'dwho' );
my $body = 'response_type=code&client_id=rpid&state=s&nonce=n&scope=openid'
  . '&redirect_uri=http%3A%2F%2Frp.com%2F';
my $par_res = $op->_post(
    '/oauth2/par', IO::String->new($body),
    accept => 'application/json',
    length => length($body),
    custom => { HTTP_AUTHORIZATION => 'Basic ' . encode_base64( 'rpid:rpid', '' ) },
);
is( $par_res->[0], 201, 'PAR request accepted' );
my $par = from_json( $par_res->[2]->[0] );

my $code = codeAuthorize(
    $op, $id,
    {
        client_id   => 'rpid',
        request_uri => $par->{request_uri},
        scope       => 'openid corporate',
    }
);
my $json  = expectJSON( codeGrant( $op, 'rpid', $code, 'http://rp.com/' ) );
my %scope = map { $_ => 1 } split /\s+/,
  getJWTPayload( $json->{access_token} )->{scope};
ok( !$scope{corporate}, 'the browser does not widen the pushed scope' );
ok( $scope{openid},     'the pushed scope is granted' );

# A signed request object overrides the pushed parameters. The core merges it
# after oidcGotRequest, so the hook must see the final scope, not the pushed
# one.
subtest 'a signed request object narrows the pushed scope' => sub {
    my $issuer = $op->p->loadedModules
      ->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
    my $jar = $issuer->createJWT(
        {
            client_id     => 'rpid',
            response_type => 'code',
            scope         => 'openid',
            redirect_uri  => 'http://rp.com/',
        },
        'HS256', 'rp'
    );

    my $push = buildForm( {
            response_type => 'code',
            client_id     => 'rpid',
            state         => 'j',
            nonce         => 'n',
            redirect_uri  => 'http://rp.com/',
            scope         => 'openid corporate',
            request       => $jar,
    } );
    my $par_res = $op->_post(
        '/oauth2/par', IO::String->new($push),
        accept => 'application/json',
        length => length($push),
        custom =>
          { HTTP_AUTHORIZATION => 'Basic ' . encode_base64( 'rpid:rpid', '' ) },
    );
    is( $par_res->[0], 201, 'PAR request with a request object accepted' );
    my $request_uri = from_json( $par_res->[2]->[0] )->{request_uri};

    my $code = codeAuthorize(
        $op, login( $op, 'dwho' ),
        {
            client_id   => 'rpid',
            request_uri => $request_uri,
        }
    );
    my $tok = expectJSON( codeGrant( $op, 'rpid', $code, 'http://rp.com/' ) );
    my %got = map { $_ => 1 } split /\s+/,
      getJWTPayload( $tok->{access_token} )->{scope};
    ok( !$got{corporate}, 'the request object does not widen the scope' );
    ok( $got{openid},     'the request object scope is granted' );
};

clean_sessions();
done_testing();
