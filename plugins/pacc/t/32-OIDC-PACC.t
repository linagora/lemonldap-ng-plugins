use warnings;
use Test::More;
use strict;
use IO::String;
use JSON qw(from_json to_json);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my $res;

# Initialize OP
my $op = LLNG::Manager::Test->new( {
        ini => {
            domain                              => 'op.com',
            portal                              => 'http://auth.op.com/',
            authentication                      => 'Demo',
            userDB                              => 'Same',
            issuerDBOpenIDConnectActivation     => 1,
            oidcServiceMetaDataIssuer           => 'http://auth.op.com',
            oidcServiceAllowDynamicRegistration => 1,

            # Load PACC plugin
            customPlugins => 'Lemonldap::NG::Portal::Plugins::PACC',

            # PACC configuration
            paccEnabled        => 1,
            paccImapEnabled    => 1,
            paccImapHostname   => 'imap.example.com',
            paccImapPort       => 993,
            paccImapAuth       => 'OAuth2 sasl-SCRAM-SHA-256-PLUS',
            paccSmtpEnabled    => 1,
            paccSmtpHostname   => 'smtp.example.com',
            paccSmtpPort       => 465,
            paccSmtpAuth       => 'OAuth2',
            paccJmapEnabled    => 1,
            paccJmapUrl        => 'https://jmap.example.com/jmap/',
            paccCalDavEnabled  => 1,
            paccCalDavUrl      => 'https://caldav.example.com/caldav/',
            paccCardDavEnabled => 1,
            paccCardDavUrl     => 'https://carddav.example.com/carddav/',
        }
    }
);

# Test 1: Get PACC metadata
ok( $res = $op->_get('/.well-known/pacc.json'), 'Get PACC metadata endpoint' );
ok( $res->[0] == 200,                           'PACC metadata returns 200' )
  or explain( $res->[0], 200 );

my $pacc = expectJSON($res);

# Test 2: Check PACC structure
ok( $pacc->{servers}, 'PACC has servers' );
ok( $pacc->{oAuth2},  'PACC has oAuth2' );

# Test 3: Check OAuth2 issuer
is( $pacc->{oAuth2}->{issuer},
    'http://auth.op.com', 'OAuth2 issuer is correct' );

# Test 4: Check IMAP configuration
ok( $pacc->{servers}->{imap}, 'IMAP server is configured' );
is( $pacc->{servers}->{imap}->{hostname},
    'imap.example.com', 'IMAP hostname is correct' );
is( $pacc->{servers}->{imap}->{port}, 993, 'IMAP port is correct' );
ok( ref( $pacc->{servers}->{imap}->{authentication} ) eq 'ARRAY',
    'IMAP authentication is an array' );
ok( grep( /^OAuth2$/, @{ $pacc->{servers}->{imap}->{authentication} } ),
    'IMAP supports OAuth2' );

# Test 5: Check SMTP configuration
ok( $pacc->{servers}->{smtp}, 'SMTP server is configured' );
is( $pacc->{servers}->{smtp}->{hostname},
    'smtp.example.com', 'SMTP hostname is correct' );
is( $pacc->{servers}->{smtp}->{port}, 465, 'SMTP port is correct' );
ok( ref( $pacc->{servers}->{smtp}->{authentication} ) eq 'ARRAY',
    'SMTP authentication is an array' );
ok( grep( /^OAuth2$/, @{ $pacc->{servers}->{smtp}->{authentication} } ),
    'SMTP supports OAuth2' );

# Test 6: Check JMAP configuration
ok( $pacc->{servers}->{jmap}, 'JMAP server is configured' );
is(
    $pacc->{servers}->{jmap}->{url},
    'https://jmap.example.com/jmap/',
    'JMAP URL is correct'
);
ok( ref( $pacc->{servers}->{jmap}->{authentication} ) eq 'ARRAY',
    'JMAP authentication is an array' );
ok( grep( /^OAuth2$/, @{ $pacc->{servers}->{jmap}->{authentication} } ),
    'JMAP supports OAuth2' );

# Test 7: Check CalDAV configuration
ok( $pacc->{servers}->{caldav}, 'CalDAV server is configured' );
is(
    $pacc->{servers}->{caldav}->{url},
    'https://caldav.example.com/caldav/',
    'CalDAV URL is correct'
);

# Test 8: Check CardDAV configuration
ok( $pacc->{servers}->{carddav}, 'CardDAV server is configured' );
is(
    $pacc->{servers}->{carddav}->{url},
    'https://carddav.example.com/carddav/',
    'CardDAV URL is correct'
);

# Test 9: PACC disabled (plugin not loaded when paccEnabled=0)
my $op_disabled = LLNG::Manager::Test->new( {
        ini => {
            domain                          => 'op.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            paccEnabled                     => 0,
        }
    }
);

ok( $res = $op_disabled->_get('/.well-known/pacc.json'),
    'Get PACC metadata when disabled' );
ok( $res->[0] == 401, 'PACC returns 401 when disabled (plugin not loaded)' )
  or explain( $res->[0], 401 );

# Test 10: PACC enabled but no servers configured
my $op_no_servers = LLNG::Manager::Test->new( {
        ini => {
            domain                          => 'op.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            customPlugins => 'Lemonldap::NG::Portal::Plugins::PACC',
            paccEnabled   => 1,
        }
    }
);

ok( $res = $op_no_servers->_get('/.well-known/pacc.json'),
    'Get PACC metadata with no servers' );
ok( $res->[0] == 503, 'PACC returns 503 when no servers configured' )
  or explain( $res->[0], 503 );

# Native client registration
my $reg_op = LLNG::Manager::Test->new( {
        ini => {
            domain                              => 'op.com',
            portal                              => 'http://auth.op.com/',
            authentication                      => 'Demo',
            userDB                              => 'Same',
            issuerDBOpenIDConnectActivation     => 1,
            oidcServiceMetaDataIssuer           => 'http://auth.op.com',
            oidcServiceMetaDataRegistrationURI  => 'register',
            oidcServiceAllowDynamicRegistration => 2,
            customPlugins => 'Lemonldap::NG::Portal::Plugins::PACC',
            paccEnabled   => 1,
            paccAllowNativeClientRegistration => 1,
            paccStrictNativeClientOnly        => 1,
            oidcServicePrivateKeySig          => oidc_key_op_private_sig(),
            oidcServicePublicKeySig           => oidc_cert_op_public_sig(),
        }
    }
);

sub register_native {
    my ( $op, $data ) = @_;
    my $json = to_json($data);
    return $op->_post(
        '/oauth2/register',
        IO::String->new($json),
        accept => 'application/json',
        type   => 'application/json',
        length => length($json),
    );
}

subtest 'PACC native client registration' => sub {
    my $res = register_native(
        $reg_op,
        {
            redirect_uris              => ['http://localhost/'],
            token_endpoint_auth_method => 'none',
        }
    );
    is( $res->[0], 201, 'a native client is registered' );
    my $client = from_json( $res->[2][0] );
    ok( $client->{client_id},      'it has a client_id' );
    ok( !$client->{client_secret}, 'a public client has no secret' );
};

subtest 'PACC strict mode rejects non-loopback redirect URIs' => sub {
    for my $uris (
        ['http://evil.example.com/'],
        [], ['http://localhost/ http://evil.example.com/'],
        ["http://localhost/\n"],
      )
    {
        my $res = register_native(
            $reg_op,
            {
                redirect_uris              => $uris,
                token_endpoint_auth_method => 'none',
            }
        );
        is( $res->[0], 400, 'refused in strict mode: ' . to_json($uris) );
    }
};

subtest 'PACC strict mode refuses metadata a native client does not need' =>
  sub {
    my %native = (
        redirect_uris              => ['http://127.0.0.1/'],
        token_endpoint_auth_method => 'none',
    );
    for my $extra (
        { request_uris            => ['https://client.example.org/req'] },
        { jwks_uri                => 'https://client.example.org/jwks' },
        { backchannel_logout_uri  => 'https://client.example.org/logout' },
        { frontchannel_logout_uri => 'http://127.0.0.1/logout' },
        { logo_uri                => 'https://client.example.org/"><b>' },
        { logo_uri                => 'javascript:alert(1)' },
        { logo_uri                => ['https://client.example.org/logo.png'] },
      )
    {
        my $res = register_native( $reg_op, { %native, %$extra } );
        is( $res->[0], 400, 'refused in strict mode: ' . to_json($extra) );
    }
    for my $extra (
        { logo_uri     => 'https://client.example.org/logo.png' },
        { request_uris => [] },
        { jwks_uri     => undef },
      )
    {
        my $res = register_native( $reg_op, { %native, %$extra } );
        is( $res->[0], 201, 'accepted in strict mode: ' . to_json($extra) );
    }
  };

my $reg_op_lax = LLNG::Manager::Test->new( {
        ini => {
            domain                              => 'op.com',
            portal                              => 'http://auth.op.com/',
            authentication                      => 'Demo',
            userDB                              => 'Same',
            issuerDBOpenIDConnectActivation     => 1,
            oidcServiceMetaDataIssuer           => 'http://auth.op.com',
            oidcServiceMetaDataRegistrationURI  => 'register',
            oidcServiceAllowDynamicRegistration => 2,
            customPlugins => 'Lemonldap::NG::Portal::Plugins::PACC',
            paccEnabled   => 1,
            paccAllowNativeClientRegistration => 1,
            paccStrictNativeClientOnly        => 0,
            oidcServicePrivateKeySig          => oidc_key_op_private_sig(),
            oidcServicePublicKeySig           => oidc_cert_op_public_sig(),
        }
    }
);

subtest 'PACC does not filter native metadata out of strict mode' => sub {
    my $res = register_native(
        $reg_op_lax,
        {
            redirect_uris              => ['http://127.0.0.1/'],
            token_endpoint_auth_method => 'none',
            frontchannel_logout_uri    => 'http://127.0.0.1/logout',
        }
    );
    is( $res->[0], 201, 'front-channel logout URI accepted' );
};

my $reg_op_no_native = LLNG::Manager::Test->new( {
        ini => {
            domain                              => 'op.com',
            portal                              => 'http://auth.op.com/',
            authentication                      => 'Demo',
            userDB                              => 'Same',
            issuerDBOpenIDConnectActivation     => 1,
            oidcServiceMetaDataIssuer           => 'http://auth.op.com',
            oidcServiceMetaDataRegistrationURI  => 'register',
            oidcServiceAllowDynamicRegistration => 2,
            customPlugins => 'Lemonldap::NG::Portal::Plugins::PACC',
            paccEnabled   => 1,
            paccAllowNativeClientRegistration => 0,
            paccStrictNativeClientOnly        => 1,
            oidcServicePrivateKeySig          => oidc_key_op_private_sig(),
            oidcServicePublicKeySig           => oidc_cert_op_public_sig(),
        }
    }
);

subtest 'PACC refuses loopback clients when native registration is disabled' =>
  sub {
    my $res = register_native(
        $reg_op_no_native,
        {
            redirect_uris              => ['http://localhost/'],
            token_endpoint_auth_method => 'none',
        }
    );
    is( $res->[0], 400, 'loopback client refused when the option is off' );
  };

clean_sessions();
done_testing();
