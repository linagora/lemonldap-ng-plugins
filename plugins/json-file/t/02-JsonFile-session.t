use strict;
use warnings;
use Test::More;
use IO::String;
use File::Temp qw(tempdir);

BEGIN {
    require 't/test-lib.pm';
}

my $dir  = tempdir( CLEANUP => 1 );
my $file = "$dir/users.json";

open my $fh, '>', $file or die "$file: $!";
print $fh '{"users":{"shadow":{"password":"shadow","_auth":"Forged",'
  . '"authenticationLevel":99,"department":"IT"}}}';
close $fh;

my $client = LLNG::Manager::Test->new( {
        ini => {
            logLevel         => 'error',
            authentication   => 'Demo',
            userDB           => 'JsonFile',
            jsonFileUserPath => $file,
        }
    }
);

my $query = 'user=shadow&password=shadow';
my $res   = $client->_post(
    '/',
    IO::String->new($query),
    length => length($query),
    accept => 'text/html',
);
my $id      = expectCookie($res);
my $session = $client->p->getApacheSession( $id, kind => q{SSO} )->data;

isnt( $session->{_auth}, 'Forged',
    '_auth is the value computed by the portal' );
isnt( $session->{authenticationLevel},
    99, 'authenticationLevel does not come from the file' );
is( $session->{department}, 'IT', 'an ordinary attribute is still exported' );

clean_sessions();
done_testing();
