use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use File::Temp qw(tempdir);

BEGIN {
    require 't/test-lib.pm';
}

# Check ssh-keygen and openssl are available
system("which ssh-keygen >/dev/null 2>&1") == 0
  or plan skip_all => "ssh-keygen not available";
system("which openssl >/dev/null 2>&1") == 0
  or plan skip_all => "openssl not available";

my $debug = 'error';

# Generate RSA key pair in PEM format for SSH CA
# RSA PEM is directly usable by ssh-keygen -s (no conversion needed)
my ( $ca_private_key, $ca_public_key );
{
    my $tmpdir = tempdir( CLEANUP => 1 );
    system(
"openssl genrsa 2048 2>/dev/null | openssl rsa -traditional -out $tmpdir/ca.key 2>/dev/null"
    ) == 0
      or plan skip_all => "openssl key generation failed";
    system("openssl rsa -in $tmpdir/ca.key -pubout -out $tmpdir/ca.pub 2>/dev/null"
    ) == 0
      or plan skip_all => "openssl pubkey extraction failed";

    local $/;
    open my $fh, '<', "$tmpdir/ca.key" or die;
    $ca_private_key = <$fh>;
    close $fh;
    open $fh, '<', "$tmpdir/ca.pub" or die;
    $ca_public_key = <$fh>;
    close $fh;
}

# Generate a user SSH public key to sign
my $user_pub_key;
{
    my $tmpdir = tempdir( CLEANUP => 1 );
    system("ssh-keygen -t ed25519 -f $tmpdir/user_key -N '' -q") == 0
      or plan skip_all => "ssh-keygen key generation failed";
    open my $fh, '<', "$tmpdir/user_key.pub" or die;
    $user_pub_key = <$fh>;
    close $fh;
    chomp $user_pub_key;
}

# Create temp directories for serial and KRL
my $tmpdir     = tempdir( CLEANUP => 1 );
my $serialPath = "$tmpdir/serial";
my $krlPath    = "$tmpdir/krl";

# ============================================
# Initialization
# ============================================

my $portal = LLNG::Manager::Test->new( {
        ini => {
            logLevel       => $debug,
            domain         => 'example.com',
            portal         => 'http://auth.example.com/',
            authentication => 'Demo',
            userDB         => 'Same',
            customPlugins  => '::Plugins::SSHCA',
            sshCaKeyRef    => 'sshca',
            keys           => {
                sshca => {
                    keyPrivate => $ca_private_key,
                    keyPublic  => $ca_public_key,
                },
            },
            sshCaKrlPath          => $krlPath,
            sshCaSerialPath       => $serialPath,
            sshCaCertMaxValidity  => 30,
            sshCaPrincipalSources => '$uid',
        }
    }
);

my $res;

# ============================================
# PART 1: Public endpoints (no auth required)
# ============================================

# GET /ssh/ca - should return SSH public key
ok(
    $res = $portal->_get(
        '/ssh/ca',
        accept => 'text/plain',
    ),
    'GET /ssh/ca'
);
expectOK($res);

my $sshPubKey = $res->[2]->[0];
ok( $sshPubKey,                         'Got SSH public key' );
like( $sshPubKey, qr/^ssh-rsa\s+/,  'Public key is in SSH RSA format' );
like( $sshPubKey, qr/LLNG-SSH-CA/,       'Public key has LLNG comment' );
count(3);

my %headers = @{ $res->[1] };
like( $headers{'Content-Type'}, qr/text\/plain/, 'Content-Type is text/plain' );
count(1);

# GET /ssh/revoked - should return empty when no KRL file exists
ok(
    $res = $portal->_get(
        '/ssh/revoked',
        accept => 'application/octet-stream',
    ),
    'GET /ssh/revoked (no KRL file)'
);
expectOK($res);
is( $res->[2]->[0], '', 'KRL is empty when file does not exist' );
count(1);

# Create a KRL file and test again
{
    open my $fh, '>', $krlPath or die "Cannot write KRL: $!";
    print $fh "FAKE_KRL_DATA";
    close $fh;
}

ok(
    $res = $portal->_get(
        '/ssh/revoked',
        accept => 'application/octet-stream',
    ),
    'GET /ssh/revoked (with KRL file)'
);
expectOK($res);
is( $res->[2]->[0], 'FAKE_KRL_DATA', 'KRL content matches file' );
count(1);

# Clean up fake KRL for later real tests
unlink $krlPath;

# ============================================
# PART 2: Authentication and signing
# ============================================

my $id = $portal->login('dwho');

# GET /ssh - should display the signing interface
ok(
    $res = $portal->_get(
        '/ssh',
        cookie => 'text/html',
        cookie => "lemonldap=$id",
    ),
    'GET /ssh interface'
);
expectOK($res);

# GET /ssh/mycerts before signing - empty
ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts before signing'
);
my $payload = expectJSON($res);
is( scalar @{ $payload->{certificates} }, 0, 'No certificates before signing' );
count(1);

# POST /ssh/sign - missing public_key
my $body = to_json( { validity_days => 1 } );
ok(
    $res = $portal->_post(
        '/ssh/sign',
        IO::String->new($body),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/sign without public_key'
);
expectReject( $res, 400 );

# POST /ssh/sign - invalid public key format
$body = to_json( { public_key => 'not-a-valid-key' } );
ok(
    $res = $portal->_post(
        '/ssh/sign',
        IO::String->new($body),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/sign with invalid public key'
);
expectReject( $res, 400 );

# POST /ssh/sign - invalid JSON body
$body = 'not valid json {{{';
ok(
    $res = $portal->_post(
        '/ssh/sign',
        IO::String->new($body),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/sign with invalid JSON'
);
expectReject( $res, 400 );

# POST /ssh/sign - valid key, first signature
$body = to_json( {
        public_key    => $user_pub_key,
        validity_days => 1,
    }
);
ok(
    $res = $portal->_post(
        '/ssh/sign',
        IO::String->new($body),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/sign with valid key'
);
$payload = expectJSON($res);
ok( $payload->{certificate},                'Got certificate' );
like( $payload->{certificate}, qr/-cert-v\d+\@openssh\.com/, 'Certificate format is correct' );
ok( $payload->{serial},                     'Got serial' );
ok( $payload->{key_id},                     'Got key_id' );
like( $payload->{key_id}, qr/dwho\@llng-/, 'Key ID contains username' );
is( ref $payload->{principals}, 'ARRAY',    'principals is an array' );
ok( grep( { $_ eq 'dwho' } @{ $payload->{principals} } ),
    'Principal contains dwho' );
ok( $payload->{valid_until}, 'Got valid_until' );
count(7);

my $serial1 = $payload->{serial};
my $key_id1 = $payload->{key_id};

# ============================================
# PART 3: Security - principals from request should be ignored
# ============================================

$body = to_json( {
        public_key    => $user_pub_key,
        validity_days => 1,
        principals    => [ 'root', 'admin' ],
    }
);
ok(
    $res = $portal->_post(
        '/ssh/sign',
        IO::String->new($body),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/sign with injected principals'
);
$payload = expectJSON($res);
ok( !grep( { $_ eq 'root' } @{ $payload->{principals} } ),
    'Injected principal root is ignored' );
ok( !grep( { $_ eq 'admin' } @{ $payload->{principals} } ),
    'Injected principal admin is ignored' );
ok( grep( { $_ eq 'dwho' } @{ $payload->{principals} } ),
    'Session-derived principal dwho is used' );
count(3);

my $serial2 = $payload->{serial};

# ============================================
# PART 4: Validity capping
# ============================================

$body = to_json( {
        public_key    => $user_pub_key,
        validity_days => 9999,
    }
);
ok(
    $res = $portal->_post(
        '/ssh/sign',
        IO::String->new($body),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/sign with excessive validity'
);
$payload = expectJSON($res);
ok( $payload->{certificate}, 'Certificate issued despite excessive validity' );
count(1);

my $serial3 = $payload->{serial};

# ============================================
# PART 5: mycerts - list signed certificates
# ============================================

ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts after 3 signatures'
);
$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} }, 3,
    'Three certificates after three signatures' );
count(1);

# Certificates are sorted newest first (by issued_at)
my @certs = @{ $payload->{certificates} };
ok( $certs[0]->{issued_at} >= $certs[2]->{issued_at},
    'Newest cert is first (by issued_at)' );
is( $certs[0]->{status}, 'active', 'Status is active' );
ok( $certs[0]->{issued_at},  'issued_at is set' );
ok( $certs[0]->{expires_at}, 'expires_at is set' );
ok( $certs[0]->{principals}, 'principals is set' );
count(6);

# ============================================
# PART 6: Persistence across sessions
# ============================================

my $id2 = $portal->login('dwho');

ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id2",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts with new session'
);
$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} }, 3,
    'Certificates persist across SSO sessions' );
count(1);

# ============================================
# PART 7: Different users have separate cert lists
# ============================================

my $id3 = $portal->login('french');

ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id3",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts as different user'
);
$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} }, 0,
    'Different user has no certificates' );
count(1);

# Sign a key as french
$body = to_json( {
        public_key    => $user_pub_key,
        validity_days => 7,
    }
);
ok(
    $res = $portal->_post(
        '/ssh/sign',
        IO::String->new($body),
        cookie => "lemonldap=$id3",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/sign as french'
);
$payload = expectJSON($res);
like( $payload->{key_id}, qr/french\@llng-/,
    'Key ID contains french username' );
ok( grep( { $_ eq 'french' } @{ $payload->{principals} } ),
    'Principal is french' );
count(2);

ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id3",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts as french after signing'
);
$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} }, 1,
    'French has 1 certificate' );
count(1);

# Verify dwho still has 3
ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id2",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts as dwho unchanged'
);
$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} }, 3,
    'dwho still has 3 certificates' );
count(1);

# ============================================
# PART 8: Unauthenticated access to auth routes
# ============================================

$body = to_json( { public_key => $user_pub_key } );
ok(
    $res = $portal->_post(
        '/ssh/sign',
        IO::String->new($body),
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/sign without cookie'
);
ok( $res->[0] != 200, 'Unauthenticated sign request is rejected' );
count(1);

clean_sessions();
done_testing();
