use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;

BEGIN {
    require 't/test-lib.pm';
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

clean_sessions();
done_testing();
