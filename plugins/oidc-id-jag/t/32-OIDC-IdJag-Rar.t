# RFC 9396 authorization_details travelling with an ID-JAG.
#
# Needs the oidc-rar plugin, declared in plugin.json:test_depends, to produce
# the granted details in the first place.
use warnings;
use Test::More;
use strict;
use utf8;
use IO::String;
use MIME::Base64 qw/encode_base64/;
use Crypt::JWT qw(decode_jwt);
use JSON;

my $rar_available =
  eval { require Lemonldap::NG::Portal::Plugins::OIDCRichAuthRequest; 1 };

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

plan skip_all => 'oidc-rar is not linked in this test tree'
  unless $rar_available;

my $ID_JAG   = 'urn:ietf:params:oauth:token-type:id-jag';
my $AUDIENCE = 'https://api.partner.com/';

my $details = encode_json( [ {
        type             => "payment_initiation",
        instructedAmount => { currency => "EUR", amount => "100.00" },
    },
    {
        type => "account_information",
    },
] );

my $op = LLNG::Manager::Test->new( {
        ini => {
            domain                          => 'op.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            customPlugins                   =>
              '::Plugins::OIDCRichAuthRequest, '
              . '::Plugins::OIDCIdentityAssertionGrant',
            issuerDBOpenIDConnectActivation => 1,
            oidcRPMetaDataExportedVars      => {
                rp  => { email => "mail", name => "cn" },
                rp2 => { email => "mail", name => "cn" },
            },
            oidcRPMetaDataOptions => {
                rp => {
                    oidcRPMetaDataOptionsDisplayName     => "RP",
                    oidcRPMetaDataOptionsClientID        => "rpid",
                    oidcRPMetaDataOptionsClientSecret    => "rpid",
                    oidcRPMetaDataOptionsIDTokenSignAlg  => "HS512",
                    oidcRPMetaDataOptionsBypassConsent   => 1,
                    oidcRPMetaDataOptionsRefreshToken    => 1,
                    oidcRPMetaDataOptionsUserIDAttr      => "",
                    oidcRPMetaDataOptionsRedirectUris    => 'http://test/',
                    oidcRPMetaDataOptionsAllowIdJagGrant => 1,

                    # oidc-rar only persists the granted details onto the
                    # access token session when it issues JWT access tokens.
                    oidcRPMetaDataOptionsAccessTokenJWT     => 1,
                    oidcRPMetaDataOptionsAccessTokenSignAlg => "RS256",
                    oidcRPMetaDataOptionsAuthorizationDetailsEnabled => 1,
                    oidcRPMetaDataOptionsAuthorizationDetailsTypes   =>
                      'payment_initiation,account_information',
                },

                # The resource only knows about payment_initiation: the other
                # entry must not travel to it.
                rp2 => {
                    oidcRPMetaDataOptionsDisplayName        => "RP2",
                    oidcRPMetaDataOptionsClientID           => "rpid2",
                    oidcRPMetaDataOptionsClientSecret       => "rpid2",
                    oidcRPMetaDataOptionsUserIDAttr         => "",
                    oidcRPMetaDataOptionsRedirectUris       => 'http://test/',
                    oidcRPMetaDataOptionsIdJagAudience      => $AUDIENCE,
                    oidcRPMetaDataOptionsTokenXAuthorizedRP => 'rp',
                    oidcRPMetaDataOptionsAuthorizationDetailsTypes =>
                      'payment_initiation',
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);

my $id   = login( $op, "french" );
my $code = codeAuthorize(
    $op, $id,
    {
        response_type         => "code",
        scope                 => "openid profile",
        client_id             => "rpid",
        state                 => "af0ifjsldkj",
        redirect_uri          => "http://test/",
        authorization_details => $details,
    }
);
my $tokens = expectJSON( codeGrant( $op, "rpid", $code, "http://test/" ) );
ok( $tokens->{authorization_details}, 'RAR details were granted' );
is( scalar @{ $tokens->{authorization_details} },
    2, 'Both entries were granted to the client' );

sub idJag {
    my (%params) = @_;
    return expectJSON(
        tokenExchange(
            $op, 'rpid',
            requested_token_type => $ID_JAG,
            audience             => $AUDIENCE,
            subject_token_type   =>
              'urn:ietf:params:oauth:token-type:refresh_token',
            subject_token => $tokens->{refresh_token},
            %params,
        )
    );
}

subtest 'authorization_details travel with the assertion' => sub {
    my $payload = decode_jwt(
        token => idJag()->{access_token},
        key   => \oidc_key_op_public_sig
    );

    my $d = $payload->{authorization_details};
    ok( $d, 'Assertion carries authorization_details' );
    is( ref($d), 'ARRAY', 'It is an array' );

    is( scalar @$d, 1, 'Only the type accepted by the target survived' );
    is( $d->[0]->{type}, 'payment_initiation', 'Correct type forwarded' );
    is( $d->[0]->{instructedAmount}->{amount},
        '100.00', 'Full entry forwarded, not just its type' );
};

subtest 'an access token subject_token carries them too' => sub {
    my $payload = decode_jwt(
        token => idJag( subject_token => $tokens->{access_token},
            subject_token_type =>
              'urn:ietf:params:oauth:token-type:access_token' )->{access_token},
        key => \oidc_key_op_public_sig
    );
    is( $payload->{authorization_details}->[0]->{type},
        'payment_initiation', 'Forwarded from the access token session' );
};

clean_sessions();
done_testing();
