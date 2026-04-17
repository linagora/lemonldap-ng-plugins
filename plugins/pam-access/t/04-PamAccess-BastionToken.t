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
# Non-existing user: JWT still generated
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
    'POST /pam/bastion-token with non-existing user'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{bastion_jwt}, 'Got JWT for non-existing user' );
count(1);

@jwt_parts = split /\./, $json->{bastion_jwt};
$payload   = from_json( decode_base64url( $jwt_parts[1] ) );
is( $payload->{sub}, 'nonexistent', 'JWT sub is non-existing user' );
count(1);

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
