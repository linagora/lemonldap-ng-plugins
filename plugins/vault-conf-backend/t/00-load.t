use strict;
use warnings;
use Test::More;
use lib 't/lib';
use MockUA;

plan skip_all =>
  "LWP::Protocol::PSGI / Plack::Request / JSON required for these tests"
  unless MockUA::deps_ok();

use_ok('Lemonldap::NG::Common::Conf');
use_ok('Lemonldap::NG::Common::Conf::Backends::OpenBAO');

is(
    $Lemonldap::NG::Common::Conf::Backends::OpenBAO::VERSION,
    '0.1.0',
    'VERSION is 0.1.0'
);

# Constants imported from Lemonldap::NG::Common::Conf::Constants
use Lemonldap::NG::Common::Conf::Constants;

ok( defined &UNKNOWN_ERROR,      'UNKNOWN_ERROR is defined' );
ok( defined &CONFIG_WAS_CHANGED, 'CONFIG_WAS_CHANGED is defined' );
ok( defined &UPLOAD_DENIED,      'UPLOAD_DENIED is defined' );

cmp_ok( UNKNOWN_ERROR,      '<', 0, 'UNKNOWN_ERROR is negative' );
cmp_ok( CONFIG_WAS_CHANGED, '<', 0, 'CONFIG_WAS_CHANGED is negative' );
cmp_ok( UPLOAD_DENIED,      '<', 0, 'UPLOAD_DENIED is negative' );

done_testing();
