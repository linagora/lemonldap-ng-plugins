use warnings;
use strict;
use Test::More;
use JSON;
use HTTP::Response;

BEGIN {
    require_ok('Lemonldap::NG::Portal::Register::LdapRest');
}

use Lemonldap::NG::Portal::Main::Constants qw(
  PE_ERROR
  PE_LDAPERROR
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
    is( $obj->restBase, 'http://ldap-rest.example.com', 'base URL' );
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
    is( $obj->computeLogin($req), PE_OK, 'login computed' );
    is( $req->data->{registerInfo}->{login}, 'jdoe', 'first letter + name' );

    # jdoe and jdoe1 are taken, jdoe2 is free
    my %taken = ( jdoe => 1, jdoe1 => 1 );
    $obj->ua(
        t::FakeUA->new(
            sub {
                my ($hreq) = @_;
                my ($id) = ( $hreq->uri->path =~ m#([^/]+)$# );
                return $taken{$id} ? found() : notFound();
            }
        )
    );
    $req = registerReq();
    is( $obj->computeLogin($req), PE_OK, 'login computed' );
    is( $req->data->{registerInfo}->{login},
        'jdoe2', 'a counter is appended' );

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
    is( $obj->computeLogin($req), PE_OK, 'login computed' );
    is( $req->data->{registerInfo}->{login}, 'jdupre', 'accents stripped' );
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
    like(
        $body->{sambaNTPassword},
        qr/^\{SSHA512\}/,
        'configured password attribute, hashed'
    );
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

done_testing();
