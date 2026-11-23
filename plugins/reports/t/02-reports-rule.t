use warnings;
use strict;
use Test::More;
use IO::String;

BEGIN {
    require 't/test-lib.pm';
}

# The /reports/* routes are portal routes: no vhost rule protects them, so
# the plugin must enforce reportsRule itself and deny when it is unset.

{
    package t::Mesg;
    sub new     { bless {}, shift }
    sub code    { 0 }
    sub entries { () }

    package t::UserDB;
    sub new          { bless {}, shift }
    sub validateLdap { 1 }
    sub ldap         { $_[0] }
    sub search       { t::Mesg->new }
}

my @routes = qw(/reports/apps /reports/browsers /reports/lastcnx);

sub portal {
    my (%extra) = @_;
    my $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel       => 'error',
                authentication => 'Demo',
                userDB         => 'Same',
                customPlugins  => '::Plugins::Reports',
                ldapBase       => 'dc=example,dc=com',
                %extra,
            }
        }
    );

    # Stub the backends once the plugin is loaded, so its own subs do not
    # replace the stubs.
    {
        no warnings 'redefine';
        no warnings 'once';
        *Lemonldap::NG::Portal::Plugins::Reports::queryDb = sub { [] };
    }
    $op->p->{loadedModules}->{'Lemonldap::NG::Portal::UserDB::LDAP'} =
      t::UserDB->new;
    return $op;
}

# Inline the login helper: LLNG 2.0.0's test-lib has no login() wrapper.
sub login {
    my ( $op, $user ) = @_;
    my $query = "user=$user&password=$user";
    my $res   = $op->_post(
        '/',
        IO::String->new($query),
        length => length($query),
    );
    expectOK($res);
    return expectCookie($res);
}

sub codes {
    my ( $op, $id ) = @_;
    return [
        map {
            $op->_get(
                $_,
                accept => 'text/csv',
                cookie => "lemonldap=$id",
            )->[0]
        } @routes
    ];
}

subtest 'reportsRule grants the matching users only' => sub {
    my $op = portal( reportsRule => '$uid eq "dwho"' );

    my $admin = login( $op, 'dwho' );
    is_deeply( codes( $op, $admin ), [ 200, 200, 200 ],
        'a user matching reportsRule gets the three reports' );

    my $user = login( $op, 'rtyler' );
    is_deeply( codes( $op, $user ), [ 403, 403, 403 ],
        'any other authenticated user gets 403 on the three reports' );
};

subtest 'no reportsRule denies everybody' => sub {
    my $op = portal();
    my $id = login( $op, 'dwho' );
    is_deeply( codes( $op, $id ), [ 403, 403, 403 ],
        'unset reportsRule: 403 on the three reports' );
};

subtest 'an empty reportsRule denies everybody' => sub {
    my $op = portal( reportsRule => '' );
    my $id = login( $op, 'dwho' );
    is_deeply( codes( $op, $id ), [ 403, 403, 403 ],
        'empty reportsRule: 403 on the three reports' );
};

subtest 'a rule that does not compile is refused' => sub {
    my $op = portal( reportsRule => '$uid eq "dwho"' );
    my $plugin =
      $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::Reports'};
    ok( $plugin, 'the plugin is loaded' );
    is( $plugin->_buildRule('$uid eq'), undef,
        'an invalid rule does not compile, so init would fail' );
    ok( !$plugin->_buildRule('0')->(), 'the default rule denies' );
};

subtest 'a database error is reported, not a crash' => sub {
    my $op = portal( reportsRule => '$uid eq "dwho"' );
    my $id = login( $op, 'dwho' );
    {
        no warnings 'redefine';
        *Lemonldap::NG::Portal::Plugins::Reports::queryDb =
          sub { die "DB unavailable\n" };
    }
    my $res = eval {
        $op->_get( '/reports/lastcnx',
            accept => 'text/csv',
            cookie => "lemonldap=$id" );
    };
    ok( $res, 'lastcnx does not die' ) or diag $@;
    isnt( $res && $res->[0], 200, 'lastcnx returns an error response' );
};

clean_sessions();
done_testing();
