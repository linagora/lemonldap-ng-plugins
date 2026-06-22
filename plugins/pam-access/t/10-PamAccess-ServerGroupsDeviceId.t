use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use MIME::Base64;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
    use FindBin;
    require "$FindBin::Bin/pam-lib.pm";
    pam_lib::install_plugin_templates();
}

# ============================================================================
# Regression: pamAccessServerGroups resolution must use the OIDC client_id,
# NOT the per-device `_deviceId`.
#
# pamAccessServerGroups is keyed by client_id (one OIDC client per project,
# the group shared by every bastion of that project). When the
# oidc-device-organization plugin is enabled, the device-grant tokens also
# carry a per-device `_deviceId` (a SHA-256 digest) which PamAccess uses as the
# audit / voucher-binding bastion identity.
#
# A previous version passed that `_deviceId` to _resolveServerGroup. Since the
# digest is never a key of pamAccessServerGroups, EVERY enrollment carrying a
# `_deviceId` was rejected with "Unknown enrolled server" at /pam/authorize and
# /pam/bastion-token — even though its client_id was correctly mapped.
#
# This test exercises exactly that combination (device-organization stamping a
# `_deviceId` + pamAccessServerGroups configured) and asserts both endpoints
# resolve the group by client_id and accept the caller, while still rejecting a
# caller-forged group that contradicts the mapping.
# ============================================================================

my $debug = 'error';
my ( $op, $res, $json );

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),

                # Add device-organization on top of base_config's plugins so
                # enrollment stamps a per-device `_deviceId` into the tokens.
                customPlugins =>
'::Plugins::PamAccess ::Plugins::OIDCDeviceAuthorization ::Plugins::OIDCDeviceOrganization',
                oidcRPMetaDataOptions => {
                    'pam-access' => {
                        oidcRPMetaDataOptionsDisplayName  => 'PAM Access',
                        oidcRPMetaDataOptionsClientID     => 'pam-access',
                        oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration    => 600,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                        oidcRPMetaDataOptionsAllowOffline             => 1,
                        oidcRPMetaDataOptionsDeviceOwnership => 'organization',
                    }
                },

                pamAccessSshRules      => { default => '1', bastion => '1' },
                pamAccessBastionGroups => 'bastion',
                pamAccessBastionJwtTtl => 300,

                # The enrolled client_id 'pam-access' is authoritatively mapped
                # to the 'bastion' group.
                pamAccessServerGroups => { 'pam-access' => 'bastion' },
            }
        }
    ),
    'OP with device-organization AND pamAccessServerGroups mapping'
);

my $id           = $op->login('french');
my $server_token = pam_lib::enroll_server( $op, $id );
ok( $server_token, 'Got server token (device-organization OP)' );
count(1);

# ----------------------------------------------------------------------------
# Sanity: confirm we really exercise the bug path — the token carries a
# `_deviceId` distinct from the shared client_id. The probe itself goes through
# _resolveServerGroup, so a 200 here already proves the resolution no longer
# rejects a device-id enrollment.
# ----------------------------------------------------------------------------
my $probe_body =
  to_json( { probe => JSON::true(), target_group => 'bastion' } );
ok(
    $res = $op->_post(
        '/pam/bastion-token',
        IO::String->new($probe_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($probe_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/bastion-token probe'
);
expectOK($res);
$json = expectJSON($res);
my $device_id = $json->{bastion_id};
like( $device_id, qr/\A[0-9a-f]{64}\z/,
    'bastion_id is the per-device SHA-256 digest' );
isnt( $device_id, 'pam-access',
    'bastion_id is the device-id, NOT the shared client_id (bug path)' );
count(2);

# ----------------------------------------------------------------------------
# /pam/authorize: the caller's body group matches the mapped group -> accepted.
# Before the fix this returned 403 "Unknown enrolled server", because the
# device-id (not the client_id) was looked up in pamAccessServerGroups.
# ----------------------------------------------------------------------------
my $auth_body = to_json( {
        user         => 'french',
        host         => 'bastion.example.com',
        server_group => 'bastion',
    }
);
ok(
    $res = $op->_post(
        '/pam/authorize',
        IO::String->new($auth_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/authorize with mapped group (device-id enrollment)'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{authorized},
    'authorized: group resolved by client_id, not device-id' );
count(1);

# A request without any body group also works: the mapping is authoritative.
my $auth_nogroup = to_json( { user => 'french', host => 'bastion.example.com' } );
ok(
    $res = $op->_post(
        '/pam/authorize',
        IO::String->new($auth_nogroup),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_nogroup),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/authorize without body group'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{authorized}, 'authorized: mapped group used when body omits it' );
count(1);

# The security control still holds: a forged group contradicting the mapping is
# rejected (the fix changes which key is looked up, not the enforcement).
my $auth_forged = to_json( {
        user         => 'french',
        host         => 'bastion.example.com',
        server_group => 'evil-forged-group',
    }
);
ok(
    $res = $op->_post(
        '/pam/authorize',
        IO::String->new($auth_forged),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_forged),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/authorize with a forged group'
);
expectReject( $res, 403 );

# ----------------------------------------------------------------------------
# /pam/bastion-token: same fix on the second call site. We first stamp the
# pam-access persistence marker for 'french' (as the real /pam flow does), then
# mint a bastion JWT and check it carries the *mapped* group.
# ----------------------------------------------------------------------------
{
    my $q = 'duration=60';
    my $r = $op->_post(
        '/pam',
        IO::String->new($q),
        accept => 'application/json',
        cookie => "lemonldap=$id",
        length => length($q),
    );
    expectOK($r);
}

my $bt_body = to_json( { user => 'french', target_host => 'backend.op.com' } );
ok(
    $res = $op->_post(
        '/pam/bastion-token',
        IO::String->new($bt_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($bt_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/bastion-token (device-id enrollment) succeeds'
);
expectOK($res);
$json = expectJSON($res);
my @parts   = split /\./, $json->{bastion_jwt};
my $payload = from_json( decode_base64url( $parts[1] ) );
is( $payload->{bastion_group}, 'bastion',
    'JWT bastion_group is the authoritative mapped value' );
count(1);

# A forged bastion_group contradicting the mapping is rejected here too.
my $bt_forged = to_json(
    { user => 'french', bastion_group => 'evil-forged-group' } );
ok(
    $res = $op->_post(
        '/pam/bastion-token',
        IO::String->new($bt_forged),
        accept => 'application/json',
        type   => 'application/json',
        length => length($bt_forged),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/bastion-token with a forged bastion_group'
);
expectReject( $res, 403 );

clean_sessions();
done_testing();

sub decode_base64url {
    my ($str) = @_;
    $str =~ tr/-_/+\//;
    my $pad = length($str) % 4;
    $str .= '=' x ( 4 - $pad ) if $pad;
    return decode_base64($str);
}
