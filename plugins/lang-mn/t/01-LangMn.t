use warnings;
use strict;
use Test::More;
use JSON;
use version;

require 't/test-lib.pm';

my $static = 'site/htdocs/static';

sub readJson {
    open my $fh, '<', $_[0] or die "$_[0]: $!";
    local $/;
    return from_json(<$fh>);
}

# Installed next to the core languages, not merged into them
ok( -f "$static/languages/mn.json", 'mn.json installed' );
ok( -f "$static/common/mn.png",     'mn flag installed' );

my $client = LLNG::Manager::Test->new(
    {
        ini => {
            languages      => 'en, fr, mn',
            authentication => 'Demo',
            userDB         => 'Same',
        }
    }
);

my $res = $client->_get(
    '/',
    accept => 'text/html',
    custom => { HTTP_ACCEPT_LANGUAGE => 'mn' }
);
is( $res->[0], 200, 'Portal answers' );
SKIP: {
    # Before 2.23, the page does not carry the language chosen by the
    # portal: the browser picks it among availableLanguages
    skip 'HTML lang attribute needs LLNG >= 2.23', 1
      if version->parse($Lemonldap::NG::Portal::VERSION) <
      version->parse('2.23.0');
    like( join( '', @{ $res->[2] } ),
        qr/<html[^>]+lang="mn"/, 'Accept-Language: mn selects Mongolian' );
}

$res = $client->_get('/psgi.js');
like(
    join( '', @{ $res->[2] } ),
    qr/availableLanguages="en, fr, mn"/,
    'mn is offered in the language choice'
);

# Keys added by a newer LLNG are displayed as their raw name: report them
my $mn      = readJson("$static/languages/mn.json");
my $en      = readJson("$static/languages/en.json");
my @missing = grep { !exists $mn->{$_} } sort keys %$en;
note "Keys missing in mn.json: @missing" if @missing;

done_testing();
