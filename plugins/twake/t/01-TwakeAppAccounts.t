use warnings;
use strict;
use Test::More;
use IO::String;
use Digest::SHA qw(sha256);

BEGIN {
    require 't/test-lib.pm';
}

my $client = LLNG::Manager::Test->new( {
        ini => {
            logLevel           => 'error',
            domain             => 'example.com',
            portal             => 'http://auth.example.com/',
            authentication     => 'Demo',
            userDB             => 'Same',
            customPlugins      => '::Plugins::TwakeAppAccounts',
            twakeAppLdapBranch => 'ou=accounts,dc=example,dc=com',
            twakeAdminTokens   => 'secret',
            portalUserAttr     => 'uid',
        }
    }
);

my $res;

# Without a session, the redirect must not contain a line break
$res = $client->_get( '/deviceaccounts', accept => 'text/html' );
is( $res->[0], 302, 'redirected to the portal' );
my $location = getHeader( $res, 'Location' );
unlike( $location, qr/[\r\n]/, 'no line break in the Location header' );

# Authenticate
my $query = 'user=dwho&password=dwho';
$res = $client->_post(
    '/',
    IO::String->new($query),
    length => length($query),
    accept => 'text/html',
);
my $id = expectCookie($res);

# The accounts page must render
$res = $client->_get(
    '/deviceaccounts',
    accept => 'text/html',
    cookie => "lemonldap=$id",
);
is( $res->[0], 200, 'the accounts page is displayed' );

$res = $client->_get( '/static/common/appaccounts.js',
    accept => 'application/javascript', );
is( $res->[0], 200, 'the accounts JavaScript is served' );

# A malformed JSON body is a 400, not a hash dereference
for my $path (qw(add del)) {
    for my $body ( '[]', '[1]', '1', '"a"', 'true' ) {
        $res = eval {
            $client->_post(
                "/deviceaccounts/$path",
                IO::String->new($body),
                accept => 'application/json',
                type   => 'application/json',
                length => length($body),
                cookie => "lemonldap=$id",
            );
        };
        is( $@,                '',  "$path $body does not die" );
        is( $res && $res->[0], 400, "$path $body gives a 400" );
    }
}

# HIDDEN__ marks a token-API account: a user cannot create one, which would
# be invisible in the list and would bypass the account limit.
for my $name ( 'HIDDEN__x', 'HIDDEN__HIDDEN__x', '  HIDDEN__x' ) {
    my $body = '{"name":"' . $name . '"}';
    $res = $client->_post(
        '/deviceaccounts/add',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        cookie => "lemonldap=$id",
    );
    is( $res->[0], 400, "a name starting with HIDDEN__ is refused ($name)" );
}

# The HTML error path uses the template that ships with the plugin
$res = $client->_post(
    '/deviceaccounts/add',
    IO::String->new('[]'),
    accept => 'text/html',
    type   => 'application/json',
    length => 2,
    cookie => "lemonldap=$id",
);
is( $res->[0], 200, 'the HTML error page is displayed' );

# The token API also refuses a non-object body
{
    package t::ApiRequest;
    sub new { return bless { env => { HTTP_AUTHORIZATION => 'secret' } }, shift }
    sub env { return $_[0]->{env} }
    sub jsonBodyToObj { return [] }

    package t::ApiPortal;
    sub new { return bless {}, shift }
    sub sendError {
        my ( $self, $req, $message, $code ) = @_;
        $self->{message} = $message;
        $self->{code}    = $code;
        return [ $code, [], [$message] ];
    }
}

my $twake = bless {
    validTokens => { sha256('secret') => 1 },
    p           => t::ApiPortal->new,
}, 'Lemonldap::NG::Portal::Plugins::TwakeAppAccounts';
$res = $twake->apiCall( t::ApiRequest->new, 'addAccount' );
is( $res->[0], 400, 'the token API refuses a non-object body' );

clean_sessions();
done_testing();
