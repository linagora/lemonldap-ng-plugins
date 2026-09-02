use warnings;
use strict;
use Test::More;
use MIME::Base64;
use Digest::SHA qw(sha1 sha256 sha512 sha256_hex hmac_sha256_hex);
use JSON;
use HTTP::Request;
use HTTP::Response;
use Encode;
use Lemonldap::NG::Common::Crypto;

BEGIN {
    require_ok('Lemonldap::NG::Portal::Password::LdapRest');
}

use Lemonldap::NG::Portal::Main::Constants;

# Minimal fake portal object: the module only needs loggers here
{

    package t::FakeLogger;
    sub new      { return bless {}, shift }
    sub AUTOLOAD { return 1 }
    sub DESTROY  { }

    package t::FakePortal;
    sub new        { return bless { logger => t::FakeLogger->new }, shift }
    sub logger     { return $_[0]->{logger} }
    sub userLogger { return $_[0]->{logger} }
    sub error      { return 1 }

    sub getFirstValue {
        my ( $self, $value ) = @_;
        my @values = split /;/, $value;
        return $values[0];
    }

    package t::FakeRequest;
    sub new { my ( $c, %a ) = @_; return bless {%a}, $c }
    sub data        { return $_[0]->{data}        ||= {} }
    sub sessionInfo { return $_[0]->{sessionInfo} ||= {} }
    sub userData    { return $_[0]->{userData}    ||= {} }

    package t::FakeUA;

    sub new {
        my ( $class, $handler ) = @_;
        return bless { handler => $handler, requests => [] }, $class;
    }

    sub request {
        my ( $self, $req ) = @_;
        push @{ $self->{requests} }, $req;
        return $self->{handler}->($req);
    }
}

my $p = t::FakePortal->new;

# "conf" is a weak reference in Lemonldap::NG::Common::Module: keep the
# hashrefs alive for the whole test
my @confs;

sub newObj {
    my (%conf) = @_;
    my $conf = {%conf};
    push @confs, $conf;
    my $obj = Lemonldap::NG::Portal::Password::LdapRest->new(
        { p => $p, conf => $conf } );

    # Skip parent inits (they need a full portal)
    no warnings 'redefine';
    local *Lemonldap::NG::Portal::Password::Base::init = sub { 1 };
    local *Lemonldap::NG::Portal::Lib::LDAP::init      = sub { 1 };
    my $res = $obj->init;
    return ( $obj, $res );
}

subtest 'init checks' => sub {
    my ( undef, $res ) = newObj();
    ok( !$res, 'ldapRestUrl is mandatory' );

    ( undef, $res ) =
      newObj( ldapRestUrl => 'http://x/', ldapRestAuthMode => 'token' );
    ok( !$res, 'token mode requires a token' );

    ( undef, $res ) =
      newObj( ldapRestUrl => 'http://x/', ldapRestAuthMode => 'hmac' );
    ok( !$res, 'hmac mode requires id and secret' );

    ( undef, $res ) =
      newObj( ldapRestUrl => 'http://x/', ldapRestAuthMode => 'foo' );
    ok( !$res, 'unknown auth mode is rejected' );

    ( undef, $res ) =
      newObj( ldapRestUrl => 'http://x/', ldapRestPasswordHash => 'BCRYPT' );
    ok( !$res, 'unknown hash scheme is rejected' );

    my $obj;
    ( $obj, $res ) = newObj( ldapRestUrl => 'http://ldap-rest.example.com/' );
    ok( $res, 'minimal configuration is accepted' );
    is(
        $obj->restBase,
        'http://ldap-rest.example.com',
        'trailing slash removed'
    );
    is( $obj->restResource, 'users',        'default resource' );
    is( $obj->restMainAttr, 'uid',          'default main attribute' );
    is( $obj->pwdAttr,      'userPassword', 'default password attribute' );
    is( $obj->restAuth,     'none',         'default auth mode' );
};

subtest 'entry path' => sub {
    my ($obj) = newObj(
        ldapRestUrl      => 'http://ldap-rest.example.com',
        ldapRestResource => 'users',
    );
    is( $obj->_collectionPath, '/api/v1/ldap/users', 'collection path' );
    is(
        $obj->_entryPath('uid=dwho,ou=users,dc=example,dc=com'),
        '/api/v1/ldap/users/uid%3Ddwho%2Cou%3Dusers%2Cdc%3Dexample%2Cdc%3Dcom',
        'DN is URL-escaped'
    );
    is( $obj->_entryPath('dwho'), '/api/v1/ldap/users/dwho', 'plain id' );
};

subtest 'password hashing' => sub {
    my ($obj) = newObj( ldapRestUrl => 'http://x' );
    is( $obj->hashPassword('secret'), 'secret', 'no scheme: cleartext' );

    my %digest = (
        SHA     => \&sha1,
        SHA256  => \&sha256,
        SHA512  => \&sha512,
        SSHA    => \&sha1,
        SSHA256 => \&sha256,
        SSHA512 => \&sha512,
    );
    for my $scheme ( sort keys %digest ) {
        my ($o) = newObj(
            ldapRestUrl          => 'http://x',
            ldapRestPasswordHash => $scheme,
        );
        my $val = $o->hashPassword('s3cr3t');
        like( $val, qr/^\{$scheme\}/, "$scheme prefix" );
        my $raw = decode_base64( substr( $val, length($scheme) + 2 ) );
        my $len = length( $digest{$scheme}->('') );
        if ( $scheme =~ /^SSHA/ ) {
            is( length($raw), $len + 8, "$scheme is salted" );
            my $salt = substr( $raw, $len );
            is(
                substr( $raw, 0, $len ),
                $digest{$scheme}->( 's3cr3t' . $salt ),
                "$scheme digest matches"
            );
        }
        else {
            is( $raw, $digest{$scheme}->('s3cr3t'), "$scheme digest matches" );
        }
    }

    my ($utf8) = newObj(
        ldapRestUrl          => 'http://x',
        ldapRestPasswordHash => 'SHA256',
    );
    my $pwd = "p\x{e9}rim\x{e8}tre";
    my $raw = decode_base64( substr( $utf8->hashPassword($pwd), 8 ) );
    is(
        $raw,
        sha256( Encode::encode( 'UTF-8', $pwd ) ),
        'password is UTF-8 encoded before hashing'
    );
};

subtest 'no authorization header' => sub {
    my ($obj) = newObj( ldapRestUrl => 'http://x' );
    my $hreq = HTTP::Request->new( PUT => 'http://x/api/v1/ldap/users/dwho' );
    $obj->setAuthorization( $hreq, 'PUT', 'http://x/api/v1/ldap/users/dwho',
        '{}' );
    ok( !$hreq->header('Authorization'), 'no Authorization header' );
};

subtest 'token authorization' => sub {
    my ($obj) = newObj(
        ldapRestUrl      => 'http://x',
        ldapRestAuthMode => 'token',
        ldapRestToken    => 'aToken',
    );
    my $hreq = HTTP::Request->new( PUT => 'http://x/api/v1/ldap/users/dwho' );
    $obj->setAuthorization( $hreq, 'PUT', 'http://x/api/v1/ldap/users/dwho',
        '{}' );
    is( $hreq->header('Authorization'), 'Bearer aToken', 'Bearer token sent' );
};

subtest 'hmac authorization' => sub {
    my $secret = 'a-secret-long-enough-to-be-realistic';
    my ($obj) = newObj(
        ldapRestUrl        => 'http://ldap-rest.example.com',
        ldapRestAuthMode   => 'hmac',
        ldapRestHmacId     => 'lemonldap',
        ldapRestHmacSecret => $secret,
    );
    my $path = '/api/v1/ldap/users/dwho';
    my $url  = 'http://ldap-rest.example.com' . $path;
    my $body = '{"replace":{"userPassword":"s3cr3t"}}';

    my $hreq = HTTP::Request->new( PUT => $url );
    $obj->setAuthorization( $hreq, 'PUT', $url, $body );
    my $h = $hreq->header('Authorization');
    like( $h, qr/^HMAC-SHA256 lemonldap:\d+:[0-9a-f]{64}$/, 'header format' );

    my ( $id, $ts, $sig ) = ( $h =~ /^HMAC-SHA256 ([^:]+):(\d+):(\w+)$/ );
    is( $id, 'lemonldap', 'service id' );
    cmp_ok( abs( $ts - time() * 1000 ), '<', 60000, 'timestamp in ms' );
    is(
        $sig,
        hmac_sha256_hex(
            join( '|', 'PUT', $path, $ts, sha256_hex($body) ), $secret
        ),
        'signature matches ldap-rest algorithm'
    );

    # GET/DELETE/HEAD are signed with an empty body hash
    $hreq = HTTP::Request->new( GET => $url );
    $obj->setAuthorization( $hreq, 'GET', $url, '' );
    ( $ts, $sig ) = ( $hreq->header('Authorization') =~ /:(\d+):(\w+)$/ );
    is(
        $sig,
        hmac_sha256_hex( join( '|', 'GET', $path, $ts, '' ), $secret ),
        'empty body hash on GET'
    );
};

subtest 'JSON body matches JSON.stringify' => sub {
    my ($obj) = newObj( ldapRestUrl => 'http://x' );
    is(
        $obj->json->encode( { replace => { userPassword => 's3cr3t' } } ),
        '{"replace":{"userPassword":"s3cr3t"}}',
        'compact JSON, no spaces'
    );
    is(
        $obj->json->encode( { replace => { cn => "\x{e9}" } } ),
        Encode::encode( 'UTF-8', '{"replace":{"cn":"' . "\x{e9}" . '"}}' ),
        'UTF-8 encoded, no \\u escaping'
    );
};

subtest 'modifyPassword sends a PUT' => sub {
    my ($obj) = newObj(
        ldapRestUrl   => 'http://ldap-rest.example.com',
        ldapRestIdKey => 'uid',
    );
    my $ua = t::FakeUA->new(
        sub {
            my $resp = HTTP::Response->new( 200, 'OK' );
            $resp->content('{"success":true}');
            return $resp;
        }
    );
    $obj->ua($ua);

    # requireOldPwdRule is set by Password::Base::init, skipped here
    $obj->requireOldPwdRule( sub { 0 } );

    my $req = t::FakeRequest->new(
        data        => { dn => 'uid=dwho,ou=users,dc=example,dc=com' },
        sessionInfo => { uid => 'dwho' },
    );

    is( $obj->modifyPassword( $req, 's3cr3t' ),
        PE_PASSWORD_OK,
        'password changed' );
    is( scalar @{ $ua->{requests} }, 1, 'one HTTP call' );
    my $sent = $ua->{requests}->[0];
    is( $sent->method, 'PUT', 'PUT method' );
    is(
        $sent->uri->as_string,
        'http://ldap-rest.example.com/api/v1/ldap/users/dwho',
        'ldapRestIdKey wins over the DN'
    );
    is(
        $sent->content,
        '{"replace":{"userPassword":"s3cr3t"}}',
        'expected body'
    );
};

subtest 'modifyPassword reports ldap-rest failures' => sub {
    my ($obj) = newObj( ldapRestUrl => 'http://ldap-rest.example.com' );
    $obj->ua(
        t::FakeUA->new(
            sub {
                my $resp = HTTP::Response->new( 403, 'Forbidden' );
                $resp->content('{"error":"forbidden"}');
                return $resp;
            }
        )
    );
    $obj->requireOldPwdRule( sub { 0 } );

    my $req = t::FakeRequest->new(
        data        => {},
        sessionInfo => { _dn => 'uid=dwho,ou=users,dc=example,dc=com' },
    );
    is( $obj->modifyPassword( $req, 's3cr3t' ),
        PE_ERROR,
        'HTTP error is reported' );
};

done_testing();
