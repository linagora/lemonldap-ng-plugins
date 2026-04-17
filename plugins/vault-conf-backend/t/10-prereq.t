use strict;
use warnings;
use Test::More;
use lib 't/lib';
use MockUA;

plan skip_all =>
  "LWP::Protocol::PSGI / Plack::Request / JSON required for these tests"
  unless MockUA::deps_ok();

use_ok('Lemonldap::NG::Common::Conf');

use Lemonldap::NG::Common::Conf::Backends::OpenBAO;

sub make_backend {
    my (%p) = @_;
    return bless \%p, 'Lemonldap::NG::Common::Conf::Backends::OpenBAO';
}

# Reset msg before each logical group
$Lemonldap::NG::Common::Conf::msg = '';

# --- missing baseUrl ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = make_backend( token => 'x' );
    my $r = $b->prereq;
    is( $r, 0, 'prereq returns 0 when baseUrl missing' );
    like(
        $Lemonldap::NG::Common::Conf::msg,
        qr/baseUrl/i,
        'msg mentions baseUrl'
    );
}

# --- missing auth (neither token nor roleId+secretId) ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = make_backend( baseUrl => 'https://bao.test/v1' );
    my $r = $b->prereq;
    is( $r, 0, 'prereq returns 0 when auth missing' );
    like(
        $Lemonldap::NG::Common::Conf::msg,
        qr/token|roleId/i,
        'msg mentions token or roleId'
    );
}

# --- only roleId (no secretId) ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = make_backend(
        baseUrl => 'https://bao.test/v1',
        roleId  => 'r1',
    );
    my $r = $b->prereq;
    is( $r, 0, 'prereq returns 0 when only roleId without secretId' );
}

# --- token AND roleId conflict ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = make_backend(
        baseUrl  => 'https://bao.test/v1',
        token    => 'tok',
        roleId   => 'rid',
        secretId => 'sid',
    );
    my $r = $b->prereq;
    is( $r, 0, 'prereq returns 0 when token and roleId both set' );
    like(
        $Lemonldap::NG::Common::Conf::msg,
        qr/mutually exclusive/i,
        'msg mentions mutually exclusive'
    );
}

# --- only token set — happy path + defaults ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = make_backend(
        baseUrl => 'https://bao.test/v1',
        token   => 'mytoken',
    );
    my $r = $b->prereq;
    is( $r, 1, 'prereq returns 1 with only token' );
    is( $b->{mount},        'secret',  'default mount=secret' );
    is( $b->{path},         'lmConf',  'default path=lmConf' );
    is( $b->{lockTtl},      60,        'default lockTtl=60' );
    is( $b->{approleMount}, 'approle', 'default approleMount=approle' );
}

# --- baseUrl missing /v<N> suffix → warning in msg but still returns 1 ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = make_backend(
        baseUrl => 'https://bao.test',
        token   => 'tok',
    );
    my $r = $b->prereq;
    is( $r, 1, 'prereq returns 1 even without /vN suffix' );
    like(
        $Lemonldap::NG::Common::Conf::msg,
        qr|/v|i,
        'msg contains warning about /vN suffix'
    );
}

# --- trailing slash on baseUrl is stripped ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = make_backend(
        baseUrl => 'https://bao.test/v1///',
        token   => 'tok',
    );
    $b->prereq;
    is( $b->{baseUrl}, 'https://bao.test/v1', 'trailing slashes stripped' );
}

# --- approle: both roleId + secretId is valid ---
{
    $Lemonldap::NG::Common::Conf::msg = '';
    my $b = make_backend(
        baseUrl  => 'https://bao.test/v1',
        roleId   => 'rid',
        secretId => 'sid',
    );
    my $r = $b->prereq;
    is( $r, 1, 'prereq returns 1 with roleId+secretId' );
}

done_testing();
