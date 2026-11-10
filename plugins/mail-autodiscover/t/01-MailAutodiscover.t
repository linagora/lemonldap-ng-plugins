use strict;
use warnings;
use Test::More;

BEGIN { require 't/test-lib.pm'; }

my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel       => 'error',
            authentication => 'Demo',
            userDB         => 'Same',
            customPlugins  => '::Plugins::MailAutodiscover',
        }
    }
);

sub body    { join '', @{ $_[0]->[2] } }
sub headers { my %h = @{ $_[0]->[1] }; \%h }

sub xml {
    my ($email) = @_;
    return $op->_get(
        '/autodiscover/autodiscover.xml',
        query => buildForm( { email => $email } )
    );
}

sub xml_expected {
    my ($value) = @_;
    $value =~ s/([&<>"'])/'&#' . ord($1) . ';'/ge;
    return $value;
}

# Valid dot-atom addresses are reflected in both LoginName elements. atext
# characters such as ', ! and / are part of the local part; the reflected
# value is XML-escaped.
for my $addr ( 'alice@example.com', "o'brien\@example.com",
    'a!b/c@example.com' )
{
    my $res = xml($addr);
    is( $res->[0], 200, "$addr: 200" );
    like( body($res),
        qr{<LoginName>\Q@{[xml_expected($addr)]}\E</LoginName>},
        "$addr: reflected in LoginName" );
}

my $res = xml('alice@example.com');
is( headers($res)->{'X-Content-Type-Options'},
    'nosniff', 'XML response carries nosniff' );
like( headers($res)->{'Content-Security-Policy'},
    qr/default-src 'none'/, 'XML response carries a restrictive CSP' );

# RFC 822 comments and quoted local parts are refused: the strict addr-spec
# does not let them through, and the value is XML-escaped as a second barrier.
my @payloads = (
    'a@b.c(<x:script xmlns:x="http://www.w3.org/1999/xhtml" src="//attacker.example/x.js"/>)',
    '"<x:script xmlns:x="http://www.w3.org/1999/xhtml">x</x:script>"@example.com',
    'a@b.c(<foo>)',
);

for my $payload (@payloads) {
    my $r = xml($payload);
    is( $r->[0], 200, 'malformed address: 200' );
    like( body($r), qr{<LoginName>%EMAILADDRESS%</LoginName>},
        'malformed address is replaced by the placeholder' );
    unlike( body($r), qr/<x:script|<foo>/,
        'malformed address is not reflected' );
}

# The escaping helper is the second barrier; test it directly.
is( Lemonldap::NG::Portal::Plugins::MailAutodiscover::_xml_escape(q{<>&"'}),
    '&#60;&#62;&#38;&#34;&#39;', '_xml_escape encodes the XML metacharacters' );

# The JSON route reads the version and the address from the path:
# /autodiscover/autodiscover.json/<version>/<email>
my $json = $op->_get(
    '/autodiscover/autodiscover.json/v1.0/alice@example.com',
    query => buildForm( { Protocol => 'AutodiscoverV1' } )
);
is( $json->[0], 200, 'JSON route accepts a valid address' );
like( body($json),
    qr{"Url":"http://auth\.example\.com/autodiscover/autodiscover\.xml"},
    'JSON route returns the XML URL without a double slash' );
is( headers($json)->{'X-Content-Type-Options'},
    'nosniff', 'JSON 200 carries nosniff' );

$json = $op->_get(
    '/autodiscover/autodiscover.json/v1.0/not-an-address',
    query => buildForm( { Protocol => 'AutodiscoverV1' } )
);
is( $json->[0], 404, 'JSON route refuses a malformed address' );
is( headers($json)->{'X-Content-Type-Options'},
    'nosniff', 'JSON 404 carries nosniff' );

# The EWS fallback does not carry a body from the request either.
my $nf = $op->_get('/EWS/Exchange.asmx');
is( $nf->[0], 404, 'EWS fallback: 404' );
is( headers($nf)->{'X-Content-Type-Options'},
    'nosniff', 'EWS fallback carries nosniff' );

done_testing();
