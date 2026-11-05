use warnings;
use strict;
use Test::More;
use JSON;
use Encode qw(decode);
use HTTP::Response;

BEGIN {
    require_ok('Lemonldap::NG::Portal::Register::LdapRest');
}

use Lemonldap::NG::Portal::Main::Constants qw(
  PE_ERROR
  PE_LDAPERROR
  PE_MALFORMEDUSER
  PE_OK
);

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

    package t::FakeRequest;
    sub new  { my ( $c, %a ) = @_; return bless {%a}, $c }
    sub data { return $_[0]->{data} ||= {} }

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
    my $obj = Lemonldap::NG::Portal::Register::LdapRest->new(
        { p => $p, conf => $conf } );
    return ( $obj, $obj->init );
}

sub notFound { return HTTP::Response->new( 404, 'Not Found' ) }

sub found {
    my $resp = HTTP::Response->new( 200, 'OK' );
    $resp->content('{"dn":"uid=jdoe,ou=users,dc=example,dc=com"}');
    return $resp;
}

sub registerReq {
    return t::FakeRequest->new(
        data => {
            registerInfo => {
                firstname => 'John',
                lastname  => 'Doe',
                mail      => 'john.doe@example.com',
                password  => 's3cr3t',
            }
        }
    );
}

subtest 'init' => sub {
    my ( undef, $res ) = newObj();
    ok( !$res, 'ldapRestUrl is mandatory' );

    my $obj;
    ( $obj, $res ) = newObj(
        ldapRestUrl           => 'http://ldap-rest.example.com/',
        ldapRestMainAttribute => 'cn',
    );
    ok( $res, 'minimal configuration is accepted' );
    is( $obj->restBase,     'http://ldap-rest.example.com', 'base URL' );
    is( $obj->restMainAttr, 'cn', 'main attribute is configurable' );

    # No LDAP connection is needed by this backend
    ok( !$obj->can('validateLdap'), 'no LDAP inheritance' );
};

subtest 'isLoginUsed' => sub {
    my ($obj) = newObj( ldapRestUrl => 'http://ldap-rest.example.com' );

    my $ua = t::FakeUA->new( sub { return notFound() } );
    $obj->ua($ua);
    is( $obj->isLoginUsed('jdoe'), 0, '404 means free' );
    is(
        $ua->{requests}->[0]->uri->as_string,
        'http://ldap-rest.example.com/api/v1/ldap/users/jdoe',
        'GET on the entry endpoint'
    );
    is( $ua->{requests}->[0]->method, 'GET', 'GET method' );

    $obj->ua( t::FakeUA->new( sub { return found() } ) );
    is( $obj->isLoginUsed('jdoe'), 1, '200 means used' );

    $obj->ua(
        t::FakeUA->new(
            sub { return HTTP::Response->new( 500, 'Server Error' ) }
        )
    );
    is( $obj->isLoginUsed('jdoe'), undef, 'other statuses are errors' );
};

subtest 'computeLogin' => sub {
    my ($obj) = newObj( ldapRestUrl => 'http://ldap-rest.example.com' );
    $obj->ua( t::FakeUA->new( sub { return notFound() } ) );

    my $req = registerReq();
    is( $obj->computeLogin($req),            PE_OK,  'login computed' );
    is( $req->data->{registerInfo}->{login}, 'jdoe', 'first letter + name' );

    # jdoe and jdoe1 are taken, jdoe2 is free
    my %taken = ( jdoe => 1, jdoe1 => 1 );
    $obj->ua(
        t::FakeUA->new(
            sub {
                my ($hreq) = @_;
                my ($id)   = ( $hreq->uri->path =~ m#([^/]+)$# );
                return $taken{$id} ? found() : notFound();
            }
        )
    );
    $req = registerReq();
    is( $obj->computeLogin($req),            PE_OK,   'login computed' );
    is( $req->data->{registerInfo}->{login}, 'jdoe2', 'a counter is appended' );

    # ldap-rest down: refuse rather than risk a duplicate
    $obj->ua(
        t::FakeUA->new(
            sub { return HTTP::Response->new( 502, 'Bad Gateway' ) }
        )
    );
    is( $obj->computeLogin( registerReq() ),
        PE_ERROR, 'lookup failure aborts registration' );

    # Everything is taken: bail out instead of looping forever
    $obj->ua( t::FakeUA->new( sub { return found() } ) );
    is( $obj->computeLogin( registerReq() ),
        PE_ERROR, 'give up after MAX_LOGIN_TRIES' );

    # Accents are stripped by Register::Base
    $req = registerReq();
    $req->data->{registerInfo}->{lastname} = "Dupr\x{e9}";
    $obj->ua( t::FakeUA->new( sub { return notFound() } ) );
    is( $obj->computeLogin($req),            PE_OK,    'login computed' );
    is( $req->data->{registerInfo}->{login}, 'jdupre', 'accents stripped' );
};

subtest 'computeLogin refuses a login made of dots' => sub {
    my ($obj) = newObj( ldapRestUrl => 'http://ldap-rest.example.com' );
    my $ua = t::FakeUA->new( sub { return notFound() } );
    $obj->ua($ua);

    my $req = registerReq();
    $req->data->{registerInfo}->{firstname} = '.';
    $req->data->{registerInfo}->{lastname}  = '.';

    isnt( $obj->computeLogin($req), PE_OK, 'login refused' );
    is( scalar @{ $ua->{requests} }, 0, 'no request sent' );
};

subtest 'createUser' => sub {
    my ($obj) = newObj( ldapRestUrl => 'http://ldap-rest.example.com' );
    my $created = HTTP::Response->new( 201, 'Created' );
    $created->content('{"dn":"uid=jdoe,ou=users,dc=example,dc=com"}');
    my $ua = t::FakeUA->new( sub { return $created } );
    $obj->ua($ua);

    my $req = registerReq();
    $req->data->{registerInfo}->{login} = 'jdoe';
    is( $obj->createUser($req), PE_OK, 'user created' );

    is( scalar @{ $ua->{requests} }, 1, 'one HTTP call' );
    my $sent = $ua->{requests}->[0];
    is( $sent->method, 'POST', 'POST method' );
    is(
        $sent->uri->as_string,
        'http://ldap-rest.example.com/api/v1/ldap/users',
        'collection endpoint'
    );
    is_deeply(
        JSON::from_json( $sent->content ),
        {
            uid          => 'jdoe',
            cn           => 'John DOE',
            sn           => 'DOE',
            givenName    => 'John',
            userPassword => 's3cr3t',
            mail         => 'john.doe@example.com',
        },
        'entry sent without objectClass (added by ldap-rest)'
    );
};

subtest 'createUser sends UTF-8 fields once' => sub {
    my ($obj) = newObj( ldapRestUrl => 'http://ldap-rest.example.com' );
    my $created = HTTP::Response->new( 201, 'Created' );
    $created->content('{}');
    my $ua = t::FakeUA->new( sub { return $created } );
    $obj->ua($ua);

    my $first_bytes = "H\xc3\xa9l\xc3\xa8ne";
    my $last_bytes  = "L\xc3\xa9v\xc3\xaaque";
    my $mail        = "helene\@example.com";
    my $first       = "H\x{e9}l\x{e8}ne";
    my $last        = "L\x{e9}v\x{ea}que";
    my $req         = registerReq();
    $req->data->{registerInfo} = {
        firstname => $first_bytes,
        lastname  => $last_bytes,
        mail      => $mail,
        password  => 's3cr3t',
        login     => 'hlev',
    };

    is( $obj->createUser($req), PE_OK, 'user created' );
    my $body = JSON->new->utf8->decode( $ua->{requests}->[0]->content );
    diag 'body gn=' . unpack(
        'H*',
        do { my $x = $body->{givenName}; utf8::encode($x); $x }
    );

    my $gn = ucfirst decode( 'UTF-8', $first_bytes );
    my $sn = uc decode( 'UTF-8', $last_bytes );
    for my $test (
        [ $body->{givenName}, $gn,       'givenName' ],
        [ $body->{sn},        $sn,       'sn' ],
        [ $body->{cn},        "$gn $sn", 'cn' ],
        [ $body->{mail},      $mail,     'mail' ]
      )
    {
        my $got = $test->[0];
        utf8::encode($got);
        my $expected = $test->[1];
        utf8::encode($expected);
        is( $got, $expected, "$test->[2] is decoded once" );
    }

    my $invalid = registerReq();
    $invalid->data->{registerInfo} = {
        firstname => "\xff",
        lastname  => 'Doe',
        mail      => 'x\@example.com',
        password  => 's3cr3t',
        login     => 'xdoe',
    };
    my $before = scalar @{ $ua->{requests} };
    is( $obj->createUser($invalid),
        PE_MALFORMEDUSER, 'invalid UTF-8 is refused' );
    is( scalar @{ $ua->{requests} }, $before, 'no request sent' );
};

subtest 'createUser honors hashing and attribute names' => sub {
    my ($obj) = newObj(
        ldapRestUrl               => 'http://ldap-rest.example.com',
        ldapRestResource          => 'people',
        ldapRestMainAttribute     => 'cn',
        ldapRestPasswordAttribute => 'sambaNTPassword',
        ldapRestPasswordHash      => 'SSHA512',
    );
    my $ua = t::FakeUA->new(
        sub {
            my $resp = HTTP::Response->new( 201, 'Created' );
            $resp->content('{}');
            return $resp;
        }
    );
    $obj->ua($ua);

    my $req = registerReq();
    $req->data->{registerInfo}->{login} = 'John DOE';
    is( $obj->createUser($req), PE_OK, 'user created' );

    my $sent = $ua->{requests}->[0];
    is(
        $sent->uri->as_string,
        'http://ldap-rest.example.com/api/v1/ldap/people',
        'configured resource'
    );
    my $body = JSON::from_json( $sent->content );
    is( $body->{cn}, 'John DOE', 'configured main attribute' );
    ok( !exists $body->{uid}, 'no uid sent' );
    like( $body->{sambaNTPassword},
        qr/^\{SSHA512\}/, 'configured password attribute, hashed' );
};

subtest 'createUser reports ldap-rest failures' => sub {
    my ($obj) = newObj( ldapRestUrl => 'http://ldap-rest.example.com' );
    $obj->ua(
        t::FakeUA->new(
            sub {
                my $resp = HTTP::Response->new( 409, 'Conflict' );
                $resp->content('{"error":"already exists"}');
                return $resp;
            }
        )
    );

    my $req = registerReq();
    $req->data->{registerInfo}->{login} = 'jdoe';
    is( $obj->createUser($req), PE_LDAPERROR, 'HTTP error is reported' );
};

subtest 'createUser reports a string false as a refusal' => sub {
    my ($obj) = newObj( ldapRestUrl => 'http://ldap-rest.example.com' );
    $obj->ua(
        t::FakeUA->new(
            sub {
                my $resp = HTTP::Response->new( 200, 'OK' );
                $resp->content('{"success":"false"}');
                return $resp;
            }
        )
    );

    my $req = registerReq();
    $req->data->{registerInfo}->{login} = 'jdoe';
    is( $obj->createUser($req), PE_LDAPERROR, 'refused creation' );
};

done_testing();
