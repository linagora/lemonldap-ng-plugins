use warnings;
use strict;
use Test::More;

# Check the documented integration path: the library is loaded by the
# `require` parameter of lemonldap-ng.ini and the functions are declared in
# `customFunctions`, LLNG then shares them with its Safe jail.

BEGIN { use_ok('Lemonldap::NG::Handler::Main::Jail') }

# Minimal API object: build_jail() only uses ->logger
{

    package TestLogger;
    our @errors;
    sub new   { return bless {}, shift }
    sub error { shift; push @errors, @_ }
    sub debug { }
    sub info  { }
    sub warn  { }

    package TestApi;
    sub logger { return TestLogger->new }
}

my $lib       = 'Lemonldap::NG::Common::CustomFunctions';
my $functions = "${lib}::uuid ${lib}::isPrivateIp";

# Both accepted syntaxes of the `require` parameter. The file path is the
# recommended one (the ini loader resolves that value as a file name), the
# module name is only understood by the jail builder.
my ($path) =
  grep { -f $_ } map { "$_/Lemonldap/NG/Common/CustomFunctions.pm" } @INC;
ok( $path, 'library file found in @INC' ) or BAIL_OUT('library not installed');

ok( !$lib->can('uuid'), 'library not loaded before the first jail is built' );

# Build a rule/macro the same way Lemonldap::NG::Handler::Main::Reload does
sub buildJail {
    my ( $useSafeJail, $require ) = @_;
    my $jail = Lemonldap::NG::Handler::Main::Jail->new( {
            useSafeJail          => $useSafeJail,
            customFunctions      => $functions,
            multiValuesSeparator => '; ',
        }
    );

    # Loading the library twice (once per `require` syntax) triggers
    # "Subroutine redefined" warnings: keep them out of the test output
    local $SIG{__WARN__} = sub { note $_[0] };

    # 2nd argument is the `require` parameter of lemonldap-ng.ini
    $jail->build_jail( 'TestApi', $require );
    return $jail;
}

sub buildSub {
    my ( $jail, $expr ) = @_;
    my $sub =
      $jail->jail_reval("sub{my (\$r,\$s)=\@_; local *_;return($expr)}");
    ok( ref($sub) eq 'CODE', "compiled: $expr" ) or diag( $jail->error );
    return $sub;
}

foreach my $case (

    # %INC is keyed by what was required: a path stays a path
    { require => $path, inc => $path, label => 'require=path' },
    {
        require => $lib,
        inc     => 'Lemonldap/NG/Common/CustomFunctions.pm',
        label   => 'require=module'
    },
  )
{
    foreach my $useSafeJail ( 1, 0 ) {
        my $mode = "$case->{label}, "
          . ( $useSafeJail ? 'with Safe jail' : 'without Safe jail' );
        @TestLogger::errors = ();
        my $jail = buildJail( $useSafeJail, $case->{require} );
        is( scalar(@TestLogger::errors),
            0, "no error while building jail ($mode)" )
          or diag( join ' ', @TestLogger::errors );
        ok( $INC{ $case->{inc} },
            "library loaded through the 'require' parameter ($mode)" );

        my $session = { uid => 'dwho', ipAddr => '10.1.2.3' };

        is(
            buildSub( $jail, 'uuid($s->{uid})' )->( {}, $session ),
            '3270ba9d-0871-5b1b-9573-cef8aeed5ec8',
            "uuid() is callable from a rule ($mode)"
        );
        is(
            buildSub( $jail, 'uuid($s->{uid}, "dns")' )->( {}, $session ),
            '3a7106e3-1d50-5caa-aba6-f727a42cfb3c',
            "uuid() accepts a namespace from a rule ($mode)"
        );
        is(
            buildSub( $jail, 'isPrivateIp($s->{ipAddr}) ? 1 : 0' )
              ->( {}, $session ),
            1,
            "isPrivateIp() is callable from a rule ($mode)"
        );
        is(
            buildSub( $jail,
                'isPrivateIp("8.8.8.8", "203.0.113.0/24") ? 1 : 0' )
              ->( {}, $session ),
            0,
            "isPrivateIp() accepts extra networks from a rule ($mode)"
        );

        # Core functions must still be available
        is(
            buildSub( $jail, 'ipInSubnet($s->{ipAddr}, "10.0.0.0/8") ? 1 : 0' )
              ->( {}, $session ),
            1,
            "core Safelib functions are still shared ($mode)"
        );
    }
}

done_testing();
