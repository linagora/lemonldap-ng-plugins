use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my $debug = 'error';

# Global scopes:
#   - "profile" is enriched with the "department" claim (existing scope,
#     must NOT be duplicated in scopes_supported)
#   - "corporate" is a brand new scope carrying two claims
my %globalScopes = (
    profile   => 'department',
    corporate => 'department title',
);

my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                        => $debug,
            domain                          => 'idp.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            oidcServiceGlobalExtraScopes    => \%globalScopes,
            oidcServicePrivateKeySig        => oidc_key_op_private_sig(),
            oidcServicePublicKeySig         => oidc_cert_op_public_sig(),
            customPlugins =>
              'Lemonldap::NG::Portal::Plugins::OIDCGlobalScopes',
        }
    }
);

my $res;
ok(
    $res = $op->_get('/.well-known/openid-configuration'),
    'Get OIDC discovery document'
);
my $metadata = expectJSON($res);

my @scopes = @{ $metadata->{scopes_supported} || [] };
my %scopes = map { $_ => 1 } @scopes;

# Core scopes are preserved
ok( $scopes{$_}, "Core scope '$_' still advertised" )
  for qw(openid profile email address phone);

# New global scope is advertised
ok( $scopes{corporate}, "Global scope 'corporate' advertised" );

# An enriched existing scope must not appear twice
is( scalar( grep { $_ eq 'profile' } @scopes ),
    1, "Enriched scope 'profile' advertised only once" );

my @claims = @{ $metadata->{claims_supported} || [] };
my %claims = map { $_ => 1 } @claims;

ok( $claims{$_}, "Core claim '$_' still advertised" )
  for qw(sub iss auth_time acr sid);

ok( $claims{department}, "Global claim 'department' advertised" );
ok( $claims{title},      "Global claim 'title' advertised" );
is( scalar( grep { $_ eq 'department' } @claims ),
    1, "Claim shared by two global scopes advertised only once" );

# ====================================================================
# Without any global scope, discovery must be left untouched
# ====================================================================

my $op2 = LLNG::Manager::Test->new( {
        ini => {
            logLevel                        => $debug,
            domain                          => 'idp.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            oidcServiceGlobalExtraScopes    => {},
            oidcServicePrivateKeySig        => oidc_key_op_private_sig(),
            oidcServicePublicKeySig         => oidc_cert_op_public_sig(),
            customPlugins =>
              'Lemonldap::NG::Portal::Plugins::OIDCGlobalScopes',
        }
    }
);

ok(
    $res = $op2->_get('/.well-known/openid-configuration'),
    'Get OIDC discovery document without global scopes'
);
my $plain = expectJSON($res);
is_deeply(
    $plain->{scopes_supported},
    [qw/openid profile email address phone/],
    'scopes_supported untouched when no global scope is configured'
);

done_testing();
