use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my $op = LLNG::Manager::Test->new( {
        ini => {
            domain                          => 'idp.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            customPlugins                   => '::Plugins::OIDCRichAuthRequest',
            issuerDBOpenIDConnectActivation => "1",
            restSessionServer               => 1,

            oidcServiceAuthorizationDetailsTypes => 'payment_initiation',
            oidcServiceAllowAuthorizationCodeFlow => 1,
            oidcServiceAllowOnlyDeclaredScopes    => 0,

            oidcRPMetaDataExportedVars =>
              { rp_consent => { email => "mail", name => "cn" } },
            oidcRPMetaDataOptions => {
                rp_consent => {
                    oidcRPMetaDataOptionsDisplayName            => "Consent RP",
                    oidcRPMetaDataOptionsIDTokenExpiration      => 3600,
                    oidcRPMetaDataOptionsClientID               => "rp_consent",
                    oidcRPMetaDataOptionsClientSecret           => "rp_consent",
                    oidcRPMetaDataOptionsIDTokenSignAlg         => "RS256",
                    oidcRPMetaDataOptionsBypassConsent          => 0,
                    oidcRPMetaDataOptionsAccessTokenExpiration  => 3600,
                    oidcRPMetaDataOptionsAccessTokenJWT         => 1,
                    oidcRPMetaDataOptionsAccessTokenSignAlg     => "RS256",
                    oidcRPMetaDataOptionsRedirectUris           => 'http://rp.com/',
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

sub details {
    my ($amount) = @_;
    return encode_json( [ {
            type             => 'payment_initiation',
            instructedAmount => { currency => 'EUR', amount => $amount },
    } ] );
}

sub authorize_with {
    my ( $id, $state, $amount ) = @_;
    return authorize(
        $op, $id,
        {
            response_type           => 'code',
            scope                   => 'openid',
            client_id               => 'rp_consent',
            state                   => $state,
            redirect_uri            => 'http://rp.com/',
            authorization_details   => details($amount),
        }
    );
}

my $id = login( $op, 'french' );

# First authorization: the consent page is shown, and the details survive the
# form submission.
my $res = authorize_with( $id, 'consent-1', '10.00' );
my ( $host, $uri, $query ) = expectForm( $res, '#', undef, 'confirm' );
like( $query, qr/authorization_details=/, 'details carried by the form' );

# The hidden confirm field holds the CSRF stamp; accepting sends confirm=1.
$query =~ s/(^|&)confirm=[^&]*/$1confirm=1/;

$res = $op->_post(
    '/oauth2/authorize',
    IO::String->new($query),
    accept => 'text/html',
    cookie => "lemonldap=$id",
    length => length($query),
);
my ($code) = expectRedirection( $res, qr#http://rp\.com/.*code=([^\&]*)# );
ok( $code, 'consent accepted, code issued' );

my $tok = expectJSON( codeGrant( $op, 'rp_consent', $code, 'http://rp.com/' ) );
is( $tok->{authorization_details}->[0]->{instructedAmount}->{amount},
    '10.00', 'the consented details are in the token' );

# Second authorization with the same scope but other details: consent is
# required again, because the stored consent records scopes only.
$res = authorize_with( $id, 'consent-2', '20.00' );
my $location = getRedirection($res) // '';
unlike( $location, qr/[?&]code=/,
    'a different authorization_details requires consent again' );

# Accept the second form: the new details, not the stored ones, must be
# carried through.
( $host, $uri, $query ) = expectForm( $res, '#', undef, 'confirm' );
$query =~ s/(^|&)confirm=[^&]*/$1confirm=1/;
$res = $op->_post(
    '/oauth2/authorize',
    IO::String->new($query),
    accept => 'text/html',
    cookie => "lemonldap=$id",
    length => length($query),
);
($code) = expectRedirection( $res, qr#http://rp\.com/.*code=([^\&]*)# );
$tok = expectJSON( codeGrant( $op, 'rp_consent', $code, 'http://rp.com/' ) );
is( $tok->{authorization_details}->[0]->{instructedAmount}->{amount},
    '20.00', 'the second consent carries the new details' );

clean_sessions();
done_testing();
