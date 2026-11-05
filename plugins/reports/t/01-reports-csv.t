use warnings;
use strict;
use utf8;
use Test::More;
use Encode qw(decode_utf8);

BEGIN {
    require 't/test-lib.pm';
}

{
    package t::Mesg;
    sub new     { my ( $c, @e ) = @_; bless { e => \@e }, $c }
    sub code    { 0 }
    sub entries { @{ $_[0]{e} } }

    package t::Entry;
    sub new       { my ( $c, %a ) = @_; bless {%a}, $c }
    sub get_value { $_[0]{ $_[1] } }

    package t::UserDB;
    our %entry;
    sub new          { bless {}, shift }
    sub validateLdap { 1 }
    sub ldap         { $_[0] }
    sub search       { t::Mesg->new( t::Entry->new(%entry) ) }
}

my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel       => 'error',
            authentication => 'Demo',
            userDB         => 'Same',
            customPlugins  => '::Plugins::Reports',
            ldapBase       => 'dc=example,dc=com',
        }
    }
);

{
    no warnings 'redefine';
    no warnings 'once';
    *Lemonldap::NG::Portal::Plugins::Reports::queryDb = sub { [] };
}
$op->p->{loadedModules}->{'Lemonldap::NG::Portal::UserDB::LDAP'} =
  t::UserDB->new;

my $id = $op->login('dwho');

sub report {
    return $op->_get(
        '/reports/lastcnx',
        accept => 'text/csv',
        cookie => "lemonldap=$id",
    );
}

subtest 'quotes are doubled and the row keeps its fields' => sub {
    %t::UserDB::entry = (
        uid                 => 'x',
        givenName           => 'Marie',
        sn                  => 'O"Neil',
        twakeDepartmentPath => 'd',
    );
    my $res = report();
    is( $res->[0], 200, 'report served' );
    like(
        $res->[2]->[0],
        qr/^"x";"never";"Marie";"O""Neil";"d"$/m,
        'the quote is doubled and the row keeps its five fields'
    );
};

subtest 'the body is UTF-8 bytes with a byte Content-Length' => sub {
    %t::UserDB::entry = (
        uid                 => 'x',
        twakeDepartmentPath => "\x{263a}",
    );
    my $res = report();
    is( $res->[0], 200, 'report served' );

    my $body = $res->[2]->[0];
    my %h    = @{ $res->[1] };
    unlike( $body, qr/[^\x00-\xff]/, 'the body is made of bytes' );
    is( $h{'Content-Length'}, length($body),
        'Content-Length counts these bytes' );
    is( $h{'Content-Type'}, 'text/csv; charset=utf-8',
        'Content-Type announces UTF-8' );
    like( decode_utf8($body), qr/"\x{263a}"/, 'the value is sent in UTF-8' );
};

clean_sessions();
done_testing();
