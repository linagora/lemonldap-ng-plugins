use strict;
use warnings;
use Test::More;

BEGIN { require 't/test-lib.pm'; }

my $client = LLNG::Manager::Test->new( {
        ini => {
            logLevel       => 'error',
            authentication => 'Demo',
            userDB         => 'Same',
            customPlugins  => '::Plugins::FixedRedirectOnLogout',
        }
    }
);

for my $value ( 'b', '/relative', 'mailto:a@b', 'file:///tmp/x' ) {
    # Keep the configuration hash alive: the base plugin stores conf as a
    # weak reference, so an anonymous hash would be freed before init().
    my $conf = { fixedLogoutRedirection => $value };
    my $o    = Lemonldap::NG::Portal::Plugins::FixedRedirectOnLogout->new( {
            p    => $client->p,
            conf => $conf,
        }
    );
    my $ret;
    my $lived = eval { $ret = $o->init; 1 };
    ok( $lived, "$value: init does not die" ) or diag $@;
    ok( !$ret,  "$value: init refuses the value" );
}

my %conf = ( fixedLogoutRedirection => 'http://logout.example.com/bye' );
my $o = Lemonldap::NG::Portal::Plugins::FixedRedirectOnLogout->new(
    { p => $client->p, conf => \%conf } );
ok( $o->init, 'a URL with a host is accepted' );
like( $conf{trustedDomains}, qr/\blogout\.example\.com\b/,
    'its host is trusted' );

done_testing();
