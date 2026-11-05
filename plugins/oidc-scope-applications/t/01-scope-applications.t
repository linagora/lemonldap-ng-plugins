use warnings;
use strict;
use Test::More;
use IO::String;
use JSON                       qw(from_json);
use Lemonldap::NG::Common::JWT qw(getJWTPayload);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my $debug = 'error';

sub build_portal {
    my ($allow_only_declared) = @_;

    return LLNG::Manager::Test->new( {
            ini => {
                logLevel                           => $debug,
                domain                             => 'idp.com',
                portal                             => 'http://auth.op.com/',
                authentication                     => 'Demo',
                userDB                             => 'Same',
                issuerDBOpenIDConnectActivation    => 1,
                oidcServiceAllowOnlyDeclaredScopes => $allow_only_declared,
                customPlugins   => '::Plugins::OIDCScopeApplications',
                applicationList => {
                    cat => {
                        catname => 'Cat',
                        type    => 'category',
                        app     => {
                            type    => 'application',
                            options => {
                                name    => 'app',
                                display => 'on',
                                logo    => 'x.png',
                                uri     => 'http://app.example.com/',
                            },
                        },
                    },
                },
                oidcRPMetaDataExportedVars => { rp => { email => 'mail' } },
                oidcRPMetaDataOptions      => {
                    rp => {
                        oidcRPMetaDataOptionsDisplayName            => 'RP',
                        oidcRPMetaDataOptionsIDTokenExpiration      => 3600,
                        oidcRPMetaDataOptionsClientID               => 'rp',
                        oidcRPMetaDataOptionsIDTokenSignAlg         => 'RS256',
                        oidcRPMetaDataOptionsClientSecret           => 'rp',
                        oidcRPMetaDataOptionsUserIDAttr             => '',
                        oidcRPMetaDataOptionsAccessTokenExpiration  => 3600,
                        oidcRPMetaDataOptionsAccessTokenJWT         => 1,
                        oidcRPMetaDataOptionsBypassConsent          => 1,
                        oidcRPMetaDataOptionsAllowScopeApplications => 1,
                        oidcRPMetaDataOptionsRedirectUris => 'http://rp.com/',
                    },
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig(),
                oidcServicePublicKeySig  => oidc_cert_op_public_sig(),
            }
        }
    );
}

sub request_scope {
    my ( $op, $id, $scope ) = @_;

    my $code = codeAuthorize(
        $op, $id,
        {
            response_type => 'code',
            scope         => "openid $scope",
            client_id     => 'rp',
            state         => 's',
            redirect_uri  => 'http://rp.com/',
        }
    );
    ok( $code, "got authorization code for '$scope'" );

    my $json    = expectJSON( codeGrant( $op, 'rp', $code, 'http://rp.com/' ) );
    my $payload = getJWTPayload( $json->{access_token} );
    my %scopes  = map { $_ => 1 } split /\s+/, $payload->{scope};
    my $userinfo =
      expectJSON( getUserinfo( $op, $json->{access_token} ) );

    return ( \%scopes, $userinfo );
}

sub check_scope {
    my ( $op, $id, $scope, $expected ) = @_;

    my ( $scopes, $userinfo ) = request_scope( $op, $id, $scope );

    is(
        $scopes->{applications} ? 1 : 0,
        $expected,
        "$scope: applications scope "
          . ( $expected ? 'granted' : 'not granted' )
    );

    is(
        exists $userinfo->{applications} ? 1 : 0,
        $expected,
        "$scope: applications claim "
          . ( $expected ? 'returned' : 'not returned' )
    );

    if ($expected) {
        is( ref from_json( $userinfo->{applications} ),
            'ARRAY', "$scope: applications claim is a JSON array" );
    }
}

# Without declared-scope filtering, every requested scope is kept in the
# token. Only the exact "applications" token must trigger the plugin.
my $op = build_portal(0);
my $id = login( $op, 'dwho' );

check_scope( $op, $id, 'applications', 1 );
check_scope( $op, $id, $_,             0 )
  for qw(my-applications applications-x applications.old applications:read);

# With declared-scope filtering, "applications" is filtered out and must be
# re-added only when it was requested as a whole token.
my $op2 = build_portal(1);
my $id2 = login( $op2, 'dwho' );

check_scope( $op2, $id2, 'applications', 1 );
check_scope( $op2, $id2, $_, 0 ) for qw(my-applications applications-x);

clean_sessions();
done_testing();
