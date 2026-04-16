use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use File::Temp;

BEGIN {
    require 't/test-lib.pm';
    eval "use Crypt::PK::Ed25519";
    plan skip_all => "Crypt::PK::Ed25519 not available" if $@;
}

# Check ssh-keygen is available
system("which ssh-keygen >/dev/null 2>&1") == 0
  or plan skip_all => "ssh-keygen not available";

my $debug = 'error';

# Generate Ed25519 key pair in PEM format for SSH CA
my ( $ca_private_key, $ca_public_key );
{
    my $pk = Crypt::PK::Ed25519->new;
    $pk->generate_key;
    $ca_private_key = $pk->export_key_pem('private');
    $ca_public_key  = $pk->export_key_pem('public');
}

# Generate a user SSH public key to sign
my $user_pub_key;
{
    my $tmpdir = File::Temp::tempdir( CLEANUP => 1 );
    system("ssh-keygen -t ed25519 -f $tmpdir/user_key -N '' -q") == 0
      or plan skip_all => "ssh-keygen key generation failed";
    open my $fh, '<', "$tmpdir/user_key.pub" or die;
    $user_pub_key = <$fh>;
    close $fh;
    chomp $user_pub_key;
}

# Create temp directories for serial and KRL
my $tmpdir     = File::Temp::tempdir( CLEANUP => 1 );
my $serialPath = "$tmpdir/serial";
my $krlPath    = "$tmpdir/krl";

# Initialization
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
            sshCaCertMaxValidity  => 365,
            sshCaPrincipalSources => '$uid',
        }
    }
);

my $res;

# Step 1: Login
my $id = $portal->login('french');

# Step 2: Check mycerts before any signing - should be empty
ok(
    $res = $portal->_get(
        "/ssh/mycerts",
        cookie => "lemonldap=$id",
        accept => 'application/json',
    ),
    "Get mycerts before signing"
);

my $payload = expectJSON($res);
ok( defined $payload->{certificates}, "certificates field exists" );
is( scalar @{ $payload->{certificates} }, 0,
    "No certificates before signing" );
count(2);

# Step 3: Sign a key
my $sign_body = to_json( {
        public_key    => $user_pub_key,
        validity_days => 1,
    }
);

ok(
    $res = $portal->_post(
        "/ssh/sign",
        IO::String->new($sign_body),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($sign_body),
    ),
    "Post sign request"
);

$payload = expectJSON($res);
ok( $payload->{certificate}, "Got certificate" );
ok( $payload->{serial},      "Got serial" );
ok( $payload->{key_id},      "Got key_id" );
ok( $payload->{principals},  "Got principals" );
is( ref $payload->{principals}, 'ARRAY', "principals is an array" );
ok( $payload->{valid_until}, "Got valid_until" );
count(5);

my $signed_serial = $payload->{serial};
my $signed_key_id = $payload->{key_id};

# Step 4: Check mycerts after signing - should show the certificate
ok(
    $res = $portal->_get(
        "/ssh/mycerts",
        cookie => "lemonldap=$id",
        accept => 'application/json',
    ),
    "Get mycerts after signing"
);

$payload = expectJSON($res);
ok( defined $payload->{certificates},     "certificates field exists" );
is( scalar @{ $payload->{certificates} }, 1, "One certificate after signing" );
count(2);

my $cert = $payload->{certificates}->[0];
is( $cert->{serial}, $signed_serial, "Serial matches" );
is( $cert->{key_id}, $signed_key_id, "Key ID matches" );
is( $cert->{status}, 'active',       "Status is active" );
ok( $cert->{issued_at},  "issued_at is set" );
ok( $cert->{expires_at}, "expires_at is set" );
ok( $cert->{principals}, "principals is set" );
count(6);

# Step 5: Sign a second key and check mycerts returns both
$sign_body = to_json( {
        public_key    => $user_pub_key,
        validity_days => 7,
    }
);

ok(
    $res = $portal->_post(
        "/ssh/sign",
        IO::String->new($sign_body),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($sign_body),
    ),
    "Post second sign request"
);

$payload = expectJSON($res);
ok( $payload->{certificate}, "Got second certificate" );
count(1);

ok(
    $res = $portal->_get(
        "/ssh/mycerts",
        cookie => "lemonldap=$id",
        accept => 'application/json',
    ),
    "Get mycerts after second signing"
);

$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} },
    2, "Two certificates after second signing" );
count(1);

# Step 6: Simulate a fresh session (re-login) and check mycerts persists
# The persistent session should survive across SSO sessions
my $id2 = $portal->login('french');

ok(
    $res = $portal->_get(
        "/ssh/mycerts",
        cookie => "lemonldap=$id2",
        accept => 'application/json',
    ),
    "Get mycerts with new session"
);

$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} },
    2, "Certificates persist across sessions" );
count(1);

clean_sessions();
done_testing();
