use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use File::Temp qw(tempdir);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
    use FindBin;
    require "$FindBin::Bin/pam-lib.pm";
    pam_lib::install_plugin_templates();
}

# This endpoint signs real SSH certificates by forking ssh-keygen, and needs
# openssl to mint the CA key — skip cleanly where they are unavailable.
system("which ssh-keygen >/dev/null 2>&1") == 0
  or plan skip_all => "ssh-keygen not available";
system("which openssl >/dev/null 2>&1") == 0
  or plan skip_all => "openssl not available";

my $debug = 'error';
my ( $op, $res );

# --- Generate an SSH CA keypair (PEM) for the ssh-ca plugin -------------------
my ( $ca_private_key, $ca_public_key );
{
    my $tmpdir = tempdir( CLEANUP => 1 );
    system(
"openssl genrsa 2048 2>/dev/null | openssl rsa -traditional -out $tmpdir/ca.key 2>/dev/null"
    ) == 0
      or plan skip_all => "openssl key generation failed";
    system(
        "openssl rsa -in $tmpdir/ca.key -pubout -out $tmpdir/ca.pub 2>/dev/null")
      == 0
      or plan skip_all => "openssl pubkey extraction failed";
    local $/;
    open my $fh, '<', "$tmpdir/ca.key" or die;
    $ca_private_key = <$fh>;
    close $fh;
    open $fh, '<', "$tmpdir/ca.pub" or die;
    $ca_public_key = <$fh>;
    close $fh;
}

# --- Generate an ephemeral user keypair (what a bastion would mint) -----------
my $eph_pubkey;
{
    my $tmpdir = tempdir( CLEANUP => 1 );
    system("ssh-keygen -t ed25519 -f $tmpdir/eph -N '' -q -C ephemeral-hop") == 0
      or plan skip_all => "ssh-keygen key generation failed";
    open my $fh, '<', "$tmpdir/eph.pub" or die;
    $eph_pubkey = <$fh>;
    close $fh;
    chomp $eph_pubkey;
}

my $krl = tempdir( CLEANUP => 1 ) . "/revoked_keys";

# --- OP with pam-access + ssh-ca (cert vouching) -----------------------------
ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),

                # Add SSHCA on top of base_config's customPlugins.
                customPlugins =>
'::Plugins::PamAccess ::Plugins::OIDCDeviceAuthorization ::Plugins::SSHCA',

                # ssh-ca CA key
                sshCaKeyRef  => 'ssh-ca',
                sshCaKrlPath => $krl,
                keys         => {
                    'ssh-ca' => {
                        keyPublic  => $ca_public_key,
                        keyPrivate => $ca_private_key,
                        keyComment => 'test ssh ca',
                    }
                },

                # 'default' is a bastion group, so an enrolled server (which
                # resolves to 'default' in legacy mode) counts as a bastion.
                pamAccessBastionGroups => 'default,bastion',
                pamAccessSshRules      => { default => '1' },
                pamAccessBastionCertTtl => 120,
            }
        }
    ),
    'OP with pam-access + ssh-ca cert vouching'
);

# ============================================================================
# Caller-gate error cases (no enrollment needed)
# ============================================================================
my $cert_body = to_json(
    { user => 'french', target_host => 'b', public_key => $eph_pubkey } );

# Without Bearer token
ok(
    $res = $op->_post(
        '/pam/bastion-cert',
        IO::String->new($cert_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($cert_body),
    ),
    'POST /pam/bastion-cert without Bearer'
);
is( $res->[0], 401, '  -> 401 without Bearer' );

# With invalid Bearer token
ok(
    $res = $op->_post(
        '/pam/bastion-cert',
        IO::String->new($cert_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($cert_body),
        custom => { HTTP_AUTHORIZATION => "Bearer invalid_xyz" },
    ),
    'POST /pam/bastion-cert with invalid Bearer'
);
is( $res->[0], 401, '  -> 401 with invalid Bearer' );

# ============================================================================
# Enroll a bastion, then run the real flow
# ============================================================================
my $id = $op->login('french');
my $server_token = pam_lib::enroll_server( $op, $id );
ok( $server_token, 'Got bastion server token' );

# Helper: POST a JSON body to a pam endpoint with the bastion Bearer.
sub bastion_post {
    my ( $path, $hash ) = @_;
    my $body = to_json($hash);
    return $op->_post(
        $path,
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    );
}

# --- /pam/authorize mints a (bastion_id, user) voucher -----------------------
$res = bastion_post( '/pam/authorize',
    { user => 'french', server_group => 'default', host => 'b1', service => 'ssh' } );
is( $res->[0], 200, '/pam/authorize 200' );
my $authz = from_json( $res->[2]->[0] );
ok( $authz->{authorized}, '  -> authorized' );
my $voucher = $authz->{bastion_voucher};
ok( $voucher, '  -> bastion_voucher present' );

# ============================================================================
# Body-validation cases (with a valid Bearer)
# ============================================================================

# Missing user
$res = bastion_post( '/pam/bastion-cert',
    { target_host => 'b', public_key => $eph_pubkey, voucher => $voucher } );
is( $res->[0], 400, 'bastion-cert without user -> 400' );

# Missing public_key
$res = bastion_post( '/pam/bastion-cert',
    { user => 'french', target_host => 'b', voucher => $voucher } );
is( $res->[0], 400, 'bastion-cert without public_key -> 400' );

# Missing voucher
$res = bastion_post( '/pam/bastion-cert',
    { user => 'french', target_host => 'b', public_key => $eph_pubkey } );
is( $res->[0], 400, 'bastion-cert without voucher -> 400' );

# Malformed public key
$res = bastion_post(
    '/pam/bastion-cert',
    {
        user        => 'french',
        target_host => 'b',
        public_key  => 'not-a-key',
        voucher     => $voucher
    }
);
is( $res->[0], 400, 'bastion-cert with malformed public_key -> 400' );

# ============================================================================
# SECURITY: voucher binding
# ============================================================================

# Wrong voucher value
$res = bastion_post(
    '/pam/bastion-cert',
    {
        user        => 'french',
        target_host => 'b',
        public_key  => $eph_pubkey,
        voucher     => 'deadbeef-0000'
    }
);
is( $res->[0], 403, 'wrong voucher -> 403' );
is( from_json( $res->[2]->[0] )->{reason},
    'voucher_mismatch', '  -> reason voucher_mismatch' );

# **KEY TEST**: a user the bastion never authorized (no voucher of their own)
# cannot get a cert, even reusing another user's voucher value.
$res = bastion_post(
    '/pam/bastion-cert',
    {
        user        => 'dwho',
        target_host => 'b',
        public_key  => $eph_pubkey,
        voucher     => $voucher
    }
);
is( $res->[0], 403, 'cert for non-vouched user (dwho) -> 403' );
is( from_json( $res->[2]->[0] )->{error},
    'voucher_rejected', '  -> voucher_rejected' );

# ============================================================================
# Successful issuance + cert contents
# ============================================================================
$res = bastion_post(
    '/pam/bastion-cert',
    {
        user         => 'french',
        target_host  => 'backend1.op.com',
        target_group => 'production',
        public_key   => $eph_pubkey,
        voucher      => $voucher,
    }
);
is( $res->[0], 200, 'valid voucher -> 200 cert issued' );
my $certresp = from_json( $res->[2]->[0] );
ok( $certresp->{certificate}, '  -> certificate returned' );
is(
    $certresp->{key_id},
    'bastion=pam-access;user=french;target=backend1.op.com',
    '  -> key_id encodes bastion/user/target'
);

# Inspect the signed certificate with ssh-keygen -L
SKIP: {
    skip "no certificate to inspect", 3 unless $certresp->{certificate};
    my $tmpdir = tempdir( CLEANUP => 1 );
    open my $fh, '>', "$tmpdir/c-cert.pub" or die;
    print $fh $certresp->{certificate};
    close $fh;
    my $L = `ssh-keygen -L -f $tmpdir/c-cert.pub 2>&1`;
    like( $L, qr/Type:\s+\S+-cert-v01\@openssh\.com user certificate/,
        '  -> is a user certificate' );
    like( $L, qr/Principals:\s*\n\s+french\b/, '  -> principal is french' );
    like( $L, qr/Key ID: "bastion=pam-access;user=french;target=backend1\.op\.com"/,
        '  -> key-id present in cert' );
}

# Voucher is REUSABLE (not consumed) -> supports multi-hop / scp host1: host2:
$res = bastion_post(
    '/pam/bastion-cert',
    {
        user        => 'french',
        target_host => 'backend2.op.com',
        public_key  => $eph_pubkey,
        voucher     => $voucher,
    }
);
is( $res->[0], 200, 'same voucher reused for a second hop -> 200' );

done_testing();
