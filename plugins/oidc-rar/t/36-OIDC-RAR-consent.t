use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use URI::Escape qw(uri_unescape);

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

# The core accepts a bare confirm=1 without the encrypted stamp, so an RP
# could append it to the authorize URL to skip the consent page. The plugin
# binds the consent to a token of its own, so the details are refused.
$res = authorize(
    $op, $id,
    {
        response_type         => 'code',
        scope                 => 'openid',
        client_id             => 'rp_consent',
        state                 => 'confirm-bypass',
        redirect_uri          => 'http://rp.com/',
        authorization_details => details('9999.00'),
        confirm               => 1,
    }
);
expectPortalError( $res, 24, 'a bare confirm=1 does not grant details' );

# A consent token from another user's page cannot be replayed: it is bound to
# the session that rendered it.
my $attacker = login( $op, 'dwho' );
my $atk_res  = authorize_with( $attacker, 'atk', '9999.00' );
my ( undef, undef, $atk_query ) = expectForm( $atk_res, '#', undef, 'confirm' );
my ($atk_token) = $atk_query =~ /lmhidden_rar_consent=([^&]+)/;
ok( $atk_token, 'attacker consent token extracted' );
$atk_token = uri_unescape($atk_token);

my $victim = login( $op, 'rtyler' );
$res = authorize(
    $op, $victim,
    {
        response_type         => 'code',
        scope                 => 'openid',
        client_id             => 'rp_consent',
        state                 => 'token-replay',
        redirect_uri          => 'http://rp.com/',
        authorization_details => details('9999.00'),
        confirm               => 1,
        lmhidden_rar_consent  => $atk_token,
    }
);
expectPortalError( $res, 24,
    "another user's consent token cannot be replayed" );

# Second authorization with the same scope but other details: consent is
# required again, because the stored consent records scopes only.
$res = authorize_with( $id, 'consent-2', '20.00' );
my $location = getRedirection($res) // '';
unlike( $location, qr/[?&]code=/,
    'a different authorization_details requires consent again' );

# Accept the second form: the new details, not the stored ones, must be
# carried through.
( $host, $uri, $query ) = expectForm( $res, '#', undef, 'confirm' );
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

# A signed request object is applied after the oidcGotRequest hook, so it can
# override the prompt the plugin forced. It must not skip the consent screen.
subtest 'a request object cannot drop the consent prompt' => sub {
    my $issuer = $op->p->loadedModules
      ->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
    my $jar = $issuer->createJWT(
        {
            client_id     => 'rp_consent',
            response_type => 'code',
            prompt        => 'none',
        },
        'HS256', 'rp_consent'
    );
    ok( defined $jar, 'signed request object built' );

    my $res = authorize(
        $op, $id,
        {
            response_type         => 'code',
            scope                 => 'openid',
            client_id             => 'rp_consent',
            state                 => 'jar-bypass',
            redirect_uri          => 'http://rp.com/',
            authorization_details => details('9999.00'),
            request               => $jar,
        }
    );
    expectPortalError( $res, 24,
        'details with a prompt=none request object are refused' );
};

clean_sessions();
done_testing();
