use warnings;
use strict;
use Test::More;
use IO::String;
use JSON;
use Lemonldap::NG::Common::JWT qw(getJWTPayload);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

# A scope both global and gated by a per-RP rule: when the rule refuses it,
# the global-scope hook must not put it back in the granted list.
my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                        => 'error',
            domain                          => 'idp.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            customPlugins => '::Plugins::OIDCGlobalScopes',
            oidcServiceGlobalExtraScopes => { refused => 'secretclaim' },
            oidcRPMetaDataScopeRules =>
              { rp => { refused => '$uid eq "dwho"' } },
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
                    oidcRPMetaDataOptionsRedirectUris => 'http://rp.com/',
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig(),
            oidcServicePublicKeySig  => oidc_cert_op_public_sig(),
        }
    }
);

sub granted {
    my ($user) = @_;
    my $id   = login( $op, $user );
    my $code = codeAuthorize(
        $op, $id,
        {
            response_type => 'code',
            scope         => 'openid refused',
            client_id     => 'rp',
            state         => 's',
            redirect_uri  => 'http://rp.com/',
        }
    );
    my $json = expectJSON( codeGrant( $op, 'rp', $code, 'http://rp.com/' ) );
    return {
        map { $_ => 1 } split /\s+/,
        getJWTPayload( $json->{access_token} )->{scope}
    };
}

ok( !granted('rtyler')->{refused}, 'a scope the rule refuses stays refused' );
ok( granted('dwho')->{refused},    'a scope the rule allows is granted' );

clean_sessions();
done_testing();
