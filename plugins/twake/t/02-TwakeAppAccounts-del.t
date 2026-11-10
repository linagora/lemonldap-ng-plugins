use strict;
use warnings;
use Test::More;
use IO::String;
use JSON qw(to_json);

BEGIN { require 't/test-lib.pm'; }

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

# Authenticate as dwho
my $query = 'user=dwho&password=dwho';
my $res   = $client->_post(
    '/',
    IO::String->new($query),
    length => length($query),
    accept => 'text/html',
);
my $id = expectCookie($res);

my $plugin =
  $client->p->loadedModules
  ->{'Lemonldap::NG::Portal::Plugins::TwakeAppAccounts'};
ok( $plugin, 'the plugin is loaded' );

# A recording LDAP that answers a single account entry.
{
    package t::Mesg;
    sub new {
        my ( $class, %args ) = @_;
        return bless { code => 0, error => '', entries => [], %args }, $class;
    }
    sub code    { $_[0]{code} }
    sub error   { $_[0]{error} }
    sub entries { @{ $_[0]{entries} } }
    sub count   { scalar @{ $_[0]{entries} } }

    package t::Entry;
    sub new       { my ( $class, %args ) = @_; bless {%args}, $class }
    sub get_value { $_[0]{ $_[1] } }

    package t::Ldap;
    our ( @SEARCHES, @DELETES, @MODIFIES );
    sub new { bless {}, shift }
    sub search {
        my ( $self, %args ) = @_;
        push @SEARCHES, $args{filter};
        return t::Mesg->new(
            entries => [
                t::Entry->new(
                    uid          => 'dwho_acc1',
                    userPassword => '{SSHA}hash',
                )
            ]
        );
    }
    sub modify { push @MODIFIES, $_[1]; return t::Mesg->new }
    sub delete { push @DELETES,  $_[1]; return t::Mesg->new }
}

my $ldap = t::Ldap->new;
$plugin->ldap($ldap);

# The caller's accounts, as getAccounts() would return them.
our $accounts       = [ { uid => 'dwho_acc1' } ];
our $accounts_error = 0;
{
    no warnings 'redefine';
    *Lemonldap::NG::Portal::Plugins::TwakeAppAccounts::getAccounts = sub {
        return ( 0, [ 500, [], ['LDAP error'] ] ) if $accounts_error;
        return $accounts;
    };
}

sub del {
    my ($uid) = @_;
    my $body = to_json( { uid => $uid } );
    return $client->_post(
        '/deviceaccounts/del',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        cookie => "lemonldap=$id",
    );
}

# A foreign account is refused before any LDAP call.
@t::Ldap::SEARCHES = ();
@t::Ldap::DELETES  = ();
$res = del('rtyler_acc1');
is( $res->[0], 400, 'a foreign uid is refused' );
is_deeply( \@t::Ldap::DELETES, [], 'nothing is deleted' );
is_deeply( \@t::Ldap::SEARCHES, [], 'no LDAP search for a foreign uid' );

# Filter metacharacters do not turn into a wildcard or a malformed filter.
$res = del('*');
is( $res->[0], 400, 'a wildcard uid is refused' );
is_deeply( \@t::Ldap::DELETES, [], 'nothing is deleted for a wildcard' );

$res = del('(');
is( $res->[0], 400, 'a malformed uid is refused' );
is_deeply( \@t::Ldap::DELETES, [], 'nothing is deleted for a malformed uid' );

# The caller's own account is deleted, with an escaped filter and DN.
@t::Ldap::SEARCHES = ();
@t::Ldap::DELETES  = ();
@t::Ldap::MODIFIES = ();
$res = del('dwho_acc1');
is( $res->[0], 200, 'the caller deletes their own account' );
is_deeply( \@t::Ldap::SEARCHES, ['(uid=dwho_acc1)'],
    'the search filter is an equality on the uid' );
is_deeply(
    \@t::Ldap::DELETES,
    ['uid=dwho_acc1,ou=accounts,dc=example,dc=com'],
    'the entry is deleted by its escaped DN'
);
is_deeply(
    \@t::Ldap::MODIFIES,
    ['uid=dwho@badwolf.org,ou=accounts,dc=example,dc=com'],
    'the password is removed from the caller Outlook entry'
);

# A uid with a filter and a DN metacharacter is escaped in both places.
$accounts = [ { uid => 'dwho_(a,b' } ];
@t::Ldap::SEARCHES = ();
@t::Ldap::DELETES  = ();
$res = del('dwho_(a,b');
is( $res->[0], 200, 'a uid with metacharacters can be deleted' );
is_deeply( \@t::Ldap::SEARCHES, ['(uid=dwho_\28a,b)'],
    'the filter escapes the parenthesis' );
is_deeply(
    \@t::Ldap::DELETES,
    ['uid=dwho_(a\,b,ou=accounts,dc=example,dc=com'],
    'the DN escapes the comma'
);

# An LDAP error from getAccounts is returned, not treated as an empty list.
$accounts_error = 1;
$res            = del('dwho_acc1');
is( $res->[0], 500, 'an LDAP error from getAccounts is propagated' );

clean_sessions();
done_testing();
