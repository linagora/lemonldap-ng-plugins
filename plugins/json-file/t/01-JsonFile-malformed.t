use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);

BEGIN {
    require 't/test-lib.pm';
}

my $dir = tempdir( CLEANUP => 1 );

sub write_file {
    my ( $name, $content ) = @_;
    open my $fh, '>', "$dir/$name" or die "$dir/$name: $!";
    print $fh $content;
    close $fh;
    return "$dir/$name";
}

my $client = LLNG::Manager::Test->new( {
        ini => {
            logLevel         => 'error',
            authentication   => 'JsonFile',
            userDB           => 'JsonFile',
            jsonFileUserPath => write_file( 'ok.json', '{"users":{"a":{}}}' ),
        }
    }
);

for my $content (
    '0',                            '"a"',
    '[]',                           '{"users":[]}',
    '{"users":"a"}',                '{"users":{"a":1}}',
    '{"users":{"a":[]}}',           '{"groups":"a"}',
    '{"groups":[]}',                '{"users":{"a":null}}',
    '{"groups":{"admins":"dwho"}}', '{"groups":{"admins":null}}',
    '{"groups":{"admins":{}}}',     '{"groups":{"admins":[null]}}',
    '{"groups":{"admins":[{}]}}'
  )
{
    my $conf   = { jsonFileUserPath => write_file( 'bad.json', $content ), };
    my $userdb = Lemonldap::NG::Portal::UserDB::JsonFile->new( {
            p    => $client->p,
            conf => $conf,
        }
    );

    my $ret;
    my $lived = eval { $ret = $userdb->init; 1 };
    ok( $lived, "$content: init does not die" ) or diag $@;
    ok( !$ret,  "$content: init refuses the file" );
}

clean_sessions();
done_testing();
