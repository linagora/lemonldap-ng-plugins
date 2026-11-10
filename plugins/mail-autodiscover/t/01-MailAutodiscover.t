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

# A valid address is reflected in both LoginName elements.
my $res = $op->_get(
    '/autodiscover/autodiscover.xml',
    query => { email => 'alice@example.com' }
);
is( $res->[0], 200, 'valid address: 200' );
like( body($res), qr{<LoginName>alice\@example\.com</LoginName>},
    'valid address is reflected in LoginName' );
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
    my $r = $op->_get(
        '/autodiscover/autodiscover.xml',
        query => { email => $payload }
    );
    is( $r->[0], 200, 'malformed address: 200' );
    unlike( body($r), qr/<x:script|<foo>/,
        'malformed address is not reflected' );
}

# The JSON route uses the same strict check.
my $json = $op->_get(
    '/autodiscover/autodiscover.json',
    query => {
        version  => 'v1.0',
        email    => 'a@b.c(<x:script>)',
        Protocol => 'AutodiscoverV1',
    }
);
is( $json->[0], 404, 'JSON route refuses the malformed address' );
is( headers($json)->{'X-Content-Type-Options'},
    'nosniff', 'JSON 404 carries nosniff' );

# The EWS fallback does not carry a body from the request either.
my $nf = $op->_get('/EWS/Exchange.asmx');
is( $nf->[0], 404, 'EWS fallback: 404' );
is( headers($nf)->{'X-Content-Type-Options'},
    'nosniff', 'EWS fallback carries nosniff' );

done_testing();
