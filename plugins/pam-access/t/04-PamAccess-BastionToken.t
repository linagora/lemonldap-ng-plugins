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

my $debug = 'error';
my ( $op, $res );

# Initialization with bastion groups including 'default'
ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),
                pamAccessSshRules => { default => '1' },
                pamAccessBastionGroups => 'default,bastion',
                pamAccessBastionJwtTtl => 300,
            }
        }
    ),
    'OP with bastion support'
);

# ============================================
# Error cases (no enrollment needed)
# ============================================

# Without Bearer token
my $bastion_body =
  to_json( { user => 'french', target_host => 'backend.example.com' } );
ok(
    $res = $op->_post(
        '/pam/bastion-token',
        IO::String->new($bastion_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($bastion_body),
    ),
    'POST /pam/bastion-token without Bearer'
);
expectReject( $res, 401 );

# With invalid Bearer token
ok(
    $res = $op->_post(
        '/pam/bastion-token',
        IO::String->new($bastion_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($bastion_body),
        custom => { HTTP_AUTHORIZATION => "Bearer invalid_xyz" },
    ),
    'POST /pam/bastion-token with invalid Bearer'
);
expectReject( $res, 401 );

# ============================================
# Enroll server and test bastion tokens
# ============================================

my $id = $op->login('french');
my $server_token = pam_lib::enroll_server( $op, $id );
ok( $server_token, 'Got server token' );
count(1);

# Stamp the pam-access persistence marker for 'french' so that
# /pam/bastion-token later recognizes them as a known user. Realistically
# this happens when the user first generates a PAM token before SSHing via
# the bastion; we reproduce that flow here.
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

# Missing user parameter
$bastion_body = to_json( { target_host => 'backend.example.com' } );
ok(
    $res = $op->_post(
        '/pam/bastion-token',
        IO::String->new($bastion_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($bastion_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/bastion-token without user'
);
expectReject( $res, 400 );

# Invalid JSON
$bastion_body = 'not valid json';
ok(
    $res = $op->_post(
        '/pam/bastion-token',
        IO::String->new($bastion_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($bastion_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/bastion-token with invalid JSON'
);
expectReject( $res, 400 );

# ============================================
# Successful JWT generation
# ============================================

$bastion_body = to_json( {
        user         => 'french',
        target_host  => 'backend.example.com',
        target_group => 'production',
    }
);
ok(
    $res = $op->_post(
        '/pam/bastion-token',
        IO::String->new($bastion_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($bastion_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/bastion-token valid request'
);
expectOK($res);
my $json = expectJSON($res);
ok( $json->{bastion_jwt}, 'Got bastion_jwt' );
ok( $json->{expires_in},  'Got expires_in' );
is( $json->{expires_in}, 300, 'Expires in 300s (configured TTL)' );
count(3);

my $jwt = $json->{bastion_jwt};

# Verify JWT structure
my @jwt_parts = split /\./, $jwt;
is( scalar(@jwt_parts), 3, 'JWT has 3 parts' );
count(1);

# Decode header
my $header = from_json( decode_base64url( $jwt_parts[0] ) );
is( $header->{alg}, 'RS256', 'JWT alg is RS256' );
is( $header->{typ}, 'JWT',   'JWT typ is JWT' );
ok( $header->{kid}, 'JWT has kid' );
count(3);

# Decode payload
my $payload = from_json( decode_base64url( $jwt_parts[1] ) );
is( $payload->{sub}, 'french', 'JWT sub is user' );
is( $payload->{aud}, 'pam:bastion-backend', 'JWT aud correct' );
is( $payload->{iss}, 'http://auth.op.com',  'JWT iss is portal' );
is( $payload->{target_host}, 'backend.example.com', 'target_host in JWT' );
is( $payload->{target_group}, 'production', 'target_group in JWT' );
ok( $payload->{exp}, 'exp present' );
ok( $payload->{iat}, 'iat present' );
ok( $payload->{jti}, 'jti present' );
ok( $payload->{bastion_id},    'bastion_id present' );
ok( $payload->{bastion_group}, 'bastion_group present' );
count(10);

# Verify expiration range
my $now = time();
ok( $payload->{exp} > $now,        'exp is in the future' );
ok( $payload->{exp} <= $now + 310, 'exp within expected range' );
count(2);

# Verify user_groups for existing user
is( ref $payload->{user_groups}, 'ARRAY', 'user_groups is array' );
count(1);

# ============================================
# _pamSeen TTL enforcement
# ============================================
# Manually rewind french's _pamSeen to simulate a stale marker and expect
# a 403 stale-marker rejection. Then restore for subsequent tests.
{
    my $ps = main::getPSession('french');
    my $orig_seen = $ps->data->{_pamSeen};
    $ps->update( { _pamSeen => time() - ( 8 * 86400 ) } );    # 8 days old

    my $stale_body = to_json( { user => 'french' } );
    ok(
        $res = $op->_post(
            '/pam/bastion-token',
            IO::String->new($stale_body),
            accept => 'application/json',
            type   => 'application/json',
            length => length($stale_body),
            custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
        ),
        'POST /pam/bastion-token with stale _pamSeen'
    );
    expectReject( $res, 403 );

    # Restore so later test blocks keep working.
    $ps = main::getPSession('french');
    $ps->update( { _pamSeen => $orig_seen || time() } );
}

# ============================================
# Non-existing user: forbidden (no persistent session on portal)
# ============================================

$bastion_body = to_json( {
        user        => 'nonexistent',
        target_host => 'backend.example.com',
    }
);
ok(
    $res = $op->_post(
        '/pam/bastion-token',
        IO::String->new($bastion_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($bastion_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/bastion-token with user lacking a persistent session'
);
expectReject( $res, 403 );

# ============================================
# Minimal parameters (defaults)
# ============================================

$bastion_body = to_json( { user => 'french' } );
ok(
    $res = $op->_post(
        '/pam/bastion-token',
        IO::String->new($bastion_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($bastion_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/bastion-token minimal params'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{bastion_jwt}, 'Got JWT with minimal params' );
count(1);

@jwt_parts = split /\./, $json->{bastion_jwt};
$payload   = from_json( decode_base64url( $jwt_parts[1] ) );
is( $payload->{target_host},  '', 'Default target_host is empty' );
is( $payload->{target_group}, 'default', 'Default target_group is "default"' );
count(2);

# ============================================================================
# Authoritative server_group resolution (pamAccessServerGroups configured)
# ----------------------------------------------------------------------------
# When the client_id->group mapping is configured, the JWT's bastion_group
# claim must come from the mapping, never from the caller-provided request
# body: /pam/bastion-token treats the group as informational, but it still must
# not sign a value the caller could forge. A body group that contradicts the
# mapping is rejected exactly as in /pam/authorize.
# ============================================================================
{
    my $op2;
    ok(
        $op2 = LLNG::Manager::Test->new( {
                ini => {
                    logLevel => $debug,
                    domain   => 'op.com',
                    portal   => 'http://auth.op.com',
                    pam_lib::base_config(),
                    pamAccessSshRules      => { default => '1' },
                    pamAccessBastionGroups => 'bastion',
                    pamAccessBastionJwtTtl => 300,

                    # The enrolled server (client_id 'pam-access') is
                    # authoritatively mapped to the 'bastion' group.
                    pamAccessServerGroups => { 'pam-access' => 'bastion' },
                }
            }
        ),
        'OP with pamAccessServerGroups mapping'
    );

    my $id2  = $op2->login('french');
    my $tok2 = pam_lib::enroll_server( $op2, $id2 );
    ok( $tok2, 'Got server token (mapped OP)' );
    count(1);

    # Stamp the _pamSeen marker for 'french' (as the real /pam flow would).
    {
        my $q = 'duration=60';
        my $r = $op2->_post(
            '/pam',
            IO::String->new($q),
            accept => 'application/json',
            cookie => "lemonldap=$id2",
            length => length($q),
        );
        expectOK($r);
    }

    # A caller-forged bastion_group that contradicts the mapping is rejected.
    my $forged = to_json(
        { user => 'french', bastion_group => 'evil-forged-group' } );
    ok(
        $res = $op2->_post(
            '/pam/bastion-token',
            IO::String->new($forged),
            accept => 'application/json',
            type   => 'application/json',
            length => length($forged),
            custom => { HTTP_AUTHORIZATION => "Bearer $tok2" },
        ),
        'POST /pam/bastion-token with a forged bastion_group'
    );
    expectReject( $res, 403 );

    # Without a contradicting body group, the JWT carries the *mapped* group.
    my $ok_body = to_json( { user => 'french' } );
    ok(
        $res = $op2->_post(
            '/pam/bastion-token',
            IO::String->new($ok_body),
            accept => 'application/json',
            type   => 'application/json',
            length => length($ok_body),
            custom => { HTTP_AUTHORIZATION => "Bearer $tok2" },
        ),
        'POST /pam/bastion-token (mapped OP) succeeds'
    );
    expectOK($res);
    my $j2 = expectJSON($res);
    my @p2 = split /\./, $j2->{bastion_jwt};
    my $pl2 = from_json( decode_base64url( $p2[1] ) );
    is( $pl2->{bastion_group}, 'bastion',
        'JWT bastion_group is the authoritative mapped value' );
    count(1);
}

clean_sessions();
done_testing();

sub decode_base64url {
    my ($str) = @_;
    $str =~ tr/-_/+\//;
    my $pad = length($str) % 4;
    $str .= '=' x ( 4 - $pad ) if $pad;
    return decode_base64($str);
}

__END__
