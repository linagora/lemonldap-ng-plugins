use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use MIME::Base64;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my $op = LLNG::Manager::Test->new( {
        ini => {
            domain                           => 'idp.com',
            portal                           => 'http://auth.op.com/',
            authentication                   => 'Demo',
            userDB                           => 'Same',
            customPlugins =>
              '::Plugins::OIDCPushedAuthRequest, '
              . '::Plugins::OIDCRichAuthRequest',
            issuerDBOpenIDConnectActivation  => "1",
            restSessionServer                => 1,
            oidcServiceMetaDataPushedAuthURI => 'par',
            oidcServicePushedAuthExpiration  => 60,

            oidcServiceAuthorizationDetailsTypes  => 'payment_initiation',
            oidcServiceAllowAuthorizationCodeFlow => 1,
            oidcServiceAllowOnlyDeclaredScopes    => 0,

            oidcRPMetaDataExportedVars =>
              { rp_par_consent => { email => "mail", name => "cn" } },
            oidcRPMetaDataOptions => {
                rp_par_consent => {
                    oidcRPMetaDataOptionsDisplayName            => "PAR consent",
                    oidcRPMetaDataOptionsIDTokenExpiration      => 3600,
                    oidcRPMetaDataOptionsClientID              => 'rp_par_consent',
                    oidcRPMetaDataOptionsClientSecret          => 'rp_par_consent',
                    oidcRPMetaDataOptionsIDTokenSignAlg         => "RS256",
                    oidcRPMetaDataOptionsBypassConsent          => 0,
                    oidcRPMetaDataOptionsAccessTokenExpiration  => 3600,
                    oidcRPMetaDataOptionsAccessTokenJWT         => 1,
                    oidcRPMetaDataOptionsAccessTokenSignAlg     => "RS256",
                    oidcRPMetaDataOptionsRedirectUris           => 'http://rp.com/',
                    oidcRPMetaDataOptionsPAR                    => 'allowed',
                    oidcRPMetaDataOptionsAuthorizationDetailsEnabled => 1,
                    oidcRPMetaDataOptionsAuthorizationDetailsTypes =>
                      'payment_initiation',
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);

my $id = login( $op, 'french' );

my $details = encode_json( [ {
        type             => 'payment_initiation',
        instructedAmount => { currency => 'EUR', amount => '10.00' },
} ] );
my $push = buildForm( {
        response_type         => 'code',
        client_id             => 'rp_par_consent',
        scope                 => 'openid',
        state                 => 'par-consent',
        redirect_uri          => 'http://rp.com/',
        authorization_details => $details,
} );
my $par_res = $op->_post(
    '/oauth2/par', IO::String->new($push),
    accept => 'application/json',
    length => length($push),
    custom => {
        HTTP_AUTHORIZATION =>
          'Basic ' . encode_base64( 'rp_par_consent:rp_par_consent', '' ),
    },
);
is( $par_res->[0], 201, 'PAR request accepted' );
my $request_uri = from_json( $par_res->[2]->[0] )->{request_uri};

# The consent form posts the request_uri again: the PAR session must survive
# until the code is issued.
my $res = authorize(
    $op, $id,
    {
        client_id   => 'rp_par_consent',
        request_uri => $request_uri,
    }
);
my ( $host, $uri, $query ) = expectForm( $res, '#', undef, 'confirm' );
$query =~ s/(^|&)confirm=[^&]*/$1confirm=1/;

$res = $op->_post(
    '/oauth2/authorize',
    IO::String->new($query),
    accept => 'text/html',
    cookie => "lemonldap=$id",
    length => length($query),
);
my ($code) = expectRedirection( $res, qr#http://rp\.com/.*code=([^\&]*)# );
ok( $code, 'consent accepted after PAR, code issued' );

my $tok =
  expectJSON( codeGrant( $op, 'rp_par_consent', $code, 'http://rp.com/' ) );
is( $tok->{authorization_details}->[0]->{instructedAmount}->{amount},
    '10.00', 'the pushed details are in the token' );

# The request_uri is single-use once the authorization is complete.
$res = authorize(
    $op, $id,
    {
        client_id   => 'rp_par_consent',
        request_uri => $request_uri,
    }
);
expectPortalError( $res, 24, 'a replayed request_uri is refused' );

clean_sessions();
done_testing();
