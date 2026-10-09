use Test::More;
use strict;
use warnings;

require 't/test-lib.pm';

my $client = LLNG::Manager::Test->new( {
        ini => {
            enabledModules =>
              'conf, sessions, notifications, 2ndFA, viewer, newManager',
        }
    }
);

sub get {
    my ( $path, $cookie ) = @_;
    return $client->app->( {
            HTTP_ACCEPT     => 'text/html',
            SCRIPT_NAME     => '',
            SERVER_NAME     => '127.0.0.1',
            QUERY_STRING    => '',
            PATH_INFO       => $path,
            REQUEST_METHOD  => 'GET',
            REQUEST_URI     => $path,
            SERVER_PORT     => '8002',
            SERVER_PROTOCOL => 'HTTP/1.1',
            REMOTE_ADDR     => '127.0.0.1',
            HTTP_HOST       => '127.0.0.1:8002',
            ( $cookie ? ( HTTP_COOKIE => $cookie ) : () ),
        }
    );
}

sub header {
    my ( $res, $name ) = @_;
    my @h = @{ $res->[1] };
    while ( my ( $k, $v ) = splice @h, 0, 2 ) {
        return $v if lc($k) eq lc($name);
    }
    return undef;
}

sub body { join '', @{ $_[0]->[2] } }

my $beta = 'llngmanagerbeta=1';
my $res;

isa_ok( $client->p, 'Lemonldap::NG::Manager::NewManager::Core' );

# Historical interface by default
$res = get('/');
is( $res->[0], 200, 'Default page' );
unlike( body($res), qr#new/\w+\.js#, 'Historical interface' );
unlike( header( $res, 'Content-Security-Policy' ),
    qr/unsafe-inline/, 'Historical CSP' );
$res = get( '/', 'llngmanagerbeta=0' );
unlike( body($res), qr#new/\w+\.js#, 'Only "1" opts in' );

# Its "New manager" tab opts in
like( body( get('/psgi.js') ), qr/"title":"newManager"/, 'Tab listed' );
$res = get('/newmanager.html');
is( $res->[0],                  302,  'Opt-in redirects' );
is( header( $res, 'Location' ), './', '... to the default page' );
like(
    header( $res, 'Set-Cookie' ),
    qr/^llngmanagerbeta=1;.*path=\//,
    '... and sets the cookie'
);

# New interface
like( body( get( '/psgi.js', $beta ) ), qr/var version='/,
    'psgi.js gives the version' );
$res = get( '/', $beta );
is( $res->[0], 200, 'New interface default page' );
like( body($res), qr#new/home\.js#, '... is the home page' );
like(
    header( $res, 'Content-Security-Policy' ),
    qr/style-src 'self' 'unsafe-inline';style-src-attr 'none'/,
    '... with the new interface CSP'
);
for my $page (qw(manager sessions notifications 2ndfa)) {
    my $bundle = $page eq '2ndfa' ? 'twofa' : $page;
    like( body( get( "/$page.html", $beta ) ),
        qr#new/$bundle\.js#, "New $page page" );
}

# Pages without a new template keep the historical one and its CSP
$res = get( '/viewer.html', $beta );
unlike( body($res), qr#new/\w+\.js#, 'Historical viewer' );
unlike( header( $res, 'Content-Security-Policy' ),
    qr/unsafe-inline/, '... with its CSP' );

# The home page only exists in the new interface
$res = get('/home.html');
is( $res->[0],                  302,  'No home page in the historical one' );
is( header( $res, 'Location' ), './', '... redirected to the default page' );

done_testing();
