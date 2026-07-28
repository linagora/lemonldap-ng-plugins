use warnings;
use strict;
use Test::More;

BEGIN { use_ok('Lemonldap::NG::Common::CustomFunctions') }

# Same aliasing as the one LemonLDAP::NG builds in its Safe jail from the
# `customFunctions` parameter
*uuid        = \&Lemonldap::NG::Common::CustomFunctions::uuid;
*isPrivateIp = \&Lemonldap::NG::Common::CustomFunctions::isPrivateIp;

# Reference values computed with Python's uuid.uuid5()

# uuid(): default namespace is 'url'
is(
    uuid('dwho'),
    '3270ba9d-0871-5b1b-9573-cef8aeed5ec8',
    'uuid() defaults to the URL namespace'
);
is( uuid( 'dwho', '6ba7b811-9dad-11d1-80b4-00c04fd430c8' ),
    uuid('dwho'), 'default namespace is the URL namespace UUID' );
is(
    uuid( 'http://example.com/', 'url' ),
    '0a300ee9-f9e4-5697-a51a-efc7fafaba67',
    'uuid() in the URL namespace'
);

# uuid(): predefined namespaces
is(
    uuid( 'example.com', 'dns' ),
    'cfbff0d1-9375-5685-968c-48ce8b15ae17',
    'uuid() in the DNS namespace'
);
is(
    uuid( '1.2.3', 'oid' ),
    '42d5e23b-3a02-5135-85c6-52d1102f1f00',
    'uuid() in the OID namespace'
);
is(
    uuid( 'cn=x', 'x500' ),
    'a951fb6d-5aab-5a72-8e2e-9aa8df8d1f8f',
    'uuid() in the X500 namespace'
);
is(
    uuid( 'example.com', 'DNS' ),
    uuid( 'example.com', 'dns' ),
    'namespace name is case insensitive'
);

# uuid(): accepted namespace syntaxes
my $expected = uuid( 'dwho', 'dns' );
is( uuid( 'dwho', '6ba7b810-9dad-11d1-80b4-00c04fd430c8' ),
    $expected, 'namespace as a canonical UUID' );
is( uuid( 'dwho', '6BA7B810-9DAD-11D1-80B4-00C04FD430C8' ),
    $expected, 'namespace as an uppercase UUID' );
is( uuid( 'dwho', '6ba7b8109dad11d180b400c04fd430c8' ),
    $expected, 'namespace without dashes' );
is( uuid( 'dwho', '{6ba7b810-9dad-11d1-80b4-00c04fd430c8}' ),
    $expected, 'namespace between braces' );
is( uuid( 'dwho', 'urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8' ),
    $expected, 'namespace as an URN' );

# uuid(): custom namespace
isnt( uuid( 'dwho', '2f4b1a10-1a2b-4c3d-8e5f-6a7b8c9d0e1f' ),
    uuid('dwho'), 'a custom namespace gives another UUID' );

# uuid(): format, stability and dispersion
like(
    uuid('dwho'),
    qr/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    'uuid() returns a canonical version 5 UUID'
);
is( uuid('dwho'), uuid('dwho'), 'uuid() is stable' );
isnt( uuid('dwho'), uuid('rtyler'), 'different values give different UUIDs' );

# uuid(): empty and undefined values
is( uuid(''), '1b4db7eb-4057-5ddf-91e0-36dec72071f5', 'uuid() of empty value' );
is( uuid(undef), uuid(''), 'undefined value is handled as an empty string' );
is( uuid( 'dwho', '' ), uuid('dwho'), 'empty namespace falls back to default' );
is( uuid( 'dwho', undef ),
    uuid('dwho'), 'undefined namespace falls back to default' );

# uuid(): the value is hashed UTF-8 encoded
my $accented = "\x{c9}ric";
utf8::upgrade($accented);
is(
    uuid($accented),
    '6801c4ae-51b2-5cda-b170-b0dca93ac361',
    'uuid() of a decoded accented value'
);
is( uuid("\xc3\x89ric"), uuid($accented),
    'UTF-8 encoded value gives the same UUID' );
is(
    uuid("\x{263a}"),
    '8a685c6c-24af-5183-a6eb-968343f75ccf',
    'uuid() of a wide character'
);

# uuid(): a wrong namespace must not silently return a constant UUID
ok(
    !eval { uuid( 'dwho', 'not-a-namespace' ); 1 },
    'uuid() dies on an invalid namespace'
);
like( $@, qr/invalid namespace/, 'uuid() error message' );

# isPrivateIp(): RFC 1918 ranges
is( isPrivateIp('10.1.2.3'),       1, '10.0.0.0/8 is private' );
is( isPrivateIp('172.16.0.1'),     1, '172.16.0.0/12 is private' );
is( isPrivateIp('172.31.255.255'), 1, 'end of 172.16.0.0/12 is private' );
is( isPrivateIp('192.168.5.5'),    1, '192.168.0.0/16 is private' );
is( isPrivateIp('172.32.0.1'),     0, '172.32.0.0 is not private' );
is( isPrivateIp('9.255.255.255'),  0, '9.255.255.255 is not private' );
is( isPrivateIp('8.8.8.8'),        0, 'a public address is not private' );
is( isPrivateIp('127.0.0.1'),      0, 'loopback is not in RFC 1918' );

# isPrivateIp(): additional networks
is( isPrivateIp( '127.0.0.1', '127.0.0.0/8' ),
    1, 'loopback with an extra network' );
is( isPrivateIp( '8.8.8.8', '127.0.0.0/8', '203.0.113.0/24' ),
    0, 'a public address stays public with extra networks' );
is( isPrivateIp('fd00::1'), 0, 'IPv6 ULA is not in RFC 1918' );
is( isPrivateIp( 'fd00::1', 'fc00::/7' ), 1, 'IPv6 ULA with an extra network' );
is( isPrivateIp( '10.1.2.3', 'fc00::/7' ),
    1, 'IPv4 private address with an IPv6 extra network' );

# isPrivateIp(): garbage in, 0 out (must never die inside a rule)
is( isPrivateIp(undef),                   0, 'undefined address' );
is( isPrivateIp(''),                      0, 'empty address' );
is( isPrivateIp('not an ip'),             0, 'unparsable address' );
is( isPrivateIp( '10.1.2.3', 'garbage' ), 0, 'unparsable extra network' );

# Function list to be declared in customFunctions
is_deeply( [ Lemonldap::NG::Common::CustomFunctions->functions ],
    [qw(uuid isPrivateIp)], 'functions() lists the provided functions' );

done_testing();
