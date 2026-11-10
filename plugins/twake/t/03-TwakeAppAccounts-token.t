use strict;
use warnings;
use Test::More;
use IO::String;
use JSON qw(to_json);

BEGIN { require 't/test-lib.pm'; }

sub call {
    my ( $client, $auth ) = @_;
    my $body = to_json( { user => 'dwho' } );
    return $client->_post(
        '/deviceaccounts/list',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        ( defined $auth ? ( custom => { HTTP_AUTHORIZATION => $auth } ) : () ),
    );
}

# A leading or doubled separator used to leave an empty alternative in the
# token regex, which made an absent Authorization header match.
for my $value ( ' secret', 'a ,b', 'a;;b' ) {
    my ($token) = grep { length } split /[;,\s]+/, $value;

    my $client = LLNG::Manager::Test->new( {
            ini => {
                logLevel           => 'error',
                domain             => 'example.com',
                portal             => 'http://auth.example.com/',
                authentication     => 'Demo',
                userDB             => 'Same',
                customPlugins      => '::Plugins::TwakeAppAccounts',
                twakeAppLdapBranch => 'ou=accounts,dc=example,dc=com',
                twakeAdminTokens   => $value,
                portalUserAttr     => 'uid',
            }
        }
    );

    my $res = call($client);
    is( $res->[0], 403, "$value: no Authorization header is refused" );

    $res = call( $client, '' );
    is( $res->[0], 403, "$value: an empty Authorization header is refused" );

    # An empty field used to become \Q\E in the runtime-built regex, which
    # matches the literal string QE. That was the actual bypass.
    $res = call( $client, 'QE' );
    is( $res->[0], 403, "$value: the QE bypass is refused" );

    # The same construction made a configured token match only Q<token>E.
    $res = call( $client, 'Q' . $token . 'E' );
    is( $res->[0], 403, "$value: the old Q<token>E literal is refused" );

    $res = call( $client, $token );
    isnt( $res->[0], 403, "$value: the configured token is accepted" );
}

# twakeAppEntryFields is an arrayref attribute: a list used to make the
# module fail to load with more than one field.
{
    my $client = LLNG::Manager::Test->new( {
            ini => {
                logLevel           => 'error',
                domain             => 'example.com',
                portal             => 'http://auth.example.com/',
                authentication     => 'Demo',
                userDB             => 'Same',
                customPlugins      => '::Plugins::TwakeAppAccounts',
                twakeAppLdapBranch => 'ou=accounts,dc=example,dc=com',
                twakeAppEntryFields => 'cn mail',
                portalUserAttr     => 'uid',
            }
        }
    );
    ok(
        $client->p->loadedModules
          ->{'Lemonldap::NG::Portal::Plugins::TwakeAppAccounts'},
        'twakeAppEntryFields with several fields loads the plugin'
    );
}

done_testing();
