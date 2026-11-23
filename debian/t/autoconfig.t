#!/usr/bin/perl
#
# open-bastion-plugins-autoconfig against a throw-away File configuration
# backend: what it writes on a new portal, and what a re-run changes on a
# configuration bootstrapped by an earlier version.
#
# Needs Lemonldap::NG::Common in @INC and openssl in PATH, e.g.:
#   PERL5LIB=.llng-test/lemonldap-ng/lemonldap-ng-common/lib prove debian/t
#
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
use JSON;

# CI sets AUTOCONFIG_TEST_STRICT so a missing dependency fails, not skips.
sub missing {
    $ENV{AUTOCONFIG_TEST_STRICT} ? BAIL_OUT( $_[0] ) : plan skip_all => $_[0];
}
BEGIN {
    eval { require Lemonldap::NG::Common::Conf; 1 }
      or missing("Lemonldap::NG::Common::Conf not in \@INC: $@");
}
missing('openssl not in PATH')
  unless grep { -x "$_/openssl" } split /:/, ( $ENV{PATH} // '' );

my $script = "$FindBin::Bin/../open-bastion-plugins-autoconfig";
my $RP     = 'pam-access';
my $DA     = 'oidcRPMetaDataOptionsAllowDeviceAuthorization';
my $ADMIN  = 'inGroup("server-admins")';

# A portal holding $conf as lmConf-1.json; returns its directory.
sub portal {
    my ($conf) = @_;
    my $dir = tempdir( CLEANUP => 1 );
    mkdir "$dir/conf" or die $!;
    _write( "$dir/conf/lmConf-1.json",
        JSON->new->canonical->encode( { cfgNum => 1, %{ $conf || {} } } ) );
    _write( "$dir/lemonldap-ng.ini",
        "[all]\n[configuration]\ntype = File\ndirName = $dir/conf\n" );
    return $dir;
}

# Run the script on that portal; returns ( exit status, output ).
sub autoconfig {
    my ( $dir, @args ) = @_;
    local $ENV{LLNG_DEFAULTCONFFILE} = "$dir/lemonldap-ng.ini";
    my $pid = open( my $fh, '-|' ) // die "fork: $!";
    if ( !$pid ) {
        open( STDERR, '>&', \*STDOUT ) or die $!;
        exec( $^X, $script, '--ssh-dir', "$dir/ssh", @args ) or die $!;
    }
    local $/;
    my $out = <$fh> // '';
    close $fh;
    return ( $? >> 8, $out );
}

# ( cfgNum, configuration ) of the latest saved configuration.
sub latest {
    my ($dir) = @_;
    my ($n) = sort { $b <=> $a } map { /lmConf-(\d+)\.json$/ ? $1 : () }
      glob("$dir/conf/lmConf-*.json");
    open( my $fh, '<', "$dir/conf/lmConf-$n.json" ) or die $!;
    local $/;
    return ( $n, decode_json(<$fh>) );
}

sub _write {
    my ( $path, $content ) = @_;
    open( my $fh, '>', $path ) or die "$path: $!";
    print $fh $content;
    close $fh;
}

# What earlier versions of the script wrote for the PAM part.
sub old_bootstrap {
    return {
        oidcRPMetaDataOptions => {
            $RP => {
                oidcRPMetaDataOptionsDisplayName => 'PAM Access',
                oidcRPMetaDataOptionsClientID    => $RP,
                oidcRPMetaDataOptionsPublic      => 1,
                oidcRPMetaDataOptionsRequirePKCE => 2,
                $DA                              => 1,
            }
        },
        oidcRPMetaDataScopeRules =>
          { $RP => { pam => '1', 'pam:server' => '1' } },
        pamAccessActivation => 1,
        pamAccessRp         => $RP,
        pamAccessSshRules   => { default => 'deny' },
    };
}

subtest 'new portal: enrollment closed, RP allowlist set' => sub {
    my $dir = portal();
    my ( $rc, $out ) = autoconfig($dir);
    is( $rc, 0, 'exit 0' ) or diag $out;
    my ( $n, $c ) = latest($dir);
    is( $n, 2, 'configuration saved' );

    is( $c->{oidcRPMetaDataOptions}{$RP}{$DA}, 0,
        'device authorization: nobody may approve an enrollment' );
    is_deeply(
        $c->{oidcRPMetaDataScopeRules}{$RP},
        { pam => '0', 'pam:server' => '0' },
        'pam and pam:server scope rules deny'
    );
    is( $c->{pamAccessAllowedRps}, $RP, 'pamAccessAllowedRps = the RP' );
    ok( !exists $c->{pamAccessRequireFingerprint},
        'pamAccessRequireFingerprint left to the admin' );
    ok( !exists $c->{pamAccessServerGroups}, 'pamAccessServerGroups not set' );
    is( $c->{sshCaAdminRule}, 0, 'sshCaAdminRule still denies' );

    like( $out, qr/before production/, 'checklist printed' );
    like( $out, qr/\[todo\] Server enrollment on RP 'pam-access' denies/,
        'checklist: enrollment closed' );
    like( $out, qr/\[ok  \] pamAccessAllowedRps = pam-access/,
        'checklist: allowlist ok' );
    like( $out, qr/\[todo\] pamAccessServerGroups is empty/,
        'checklist: server groups' );
    like( $out, qr/allowed_bastions/, 'checklist: backends' );

    ( $rc, $out ) = autoconfig($dir);
    is( $rc, 0, 're-run: exit 0' );
    like( $out, qr/Nothing to do/, 're-run: idempotent' );
    is( ( latest($dir) )[0], 2, 're-run: nothing saved' );
};

subtest 'new portal with --server-admin-rule and --require-fingerprint' =>
  sub {
    my $dir = portal();
    my ( $rc, $out ) = autoconfig( $dir, '--server-admin-rule', " $ADMIN ",
        '--require-fingerprint' );
    is( $rc, 0, 'exit 0' ) or diag $out;
    my ( undef, $c ) = latest($dir);
    is( $c->{oidcRPMetaDataOptions}{$RP}{$DA}, $ADMIN, 'approver rule' );
    is_deeply(
        $c->{oidcRPMetaDataScopeRules}{$RP},
        { pam => $ADMIN, 'pam:server' => $ADMIN },
        'scope rules follow the approver rule'
    );
    is( $c->{pamAccessRequireFingerprint}, 1, 'pamAccessRequireFingerprint' );
    like( $out, qr/\[ok  \] Server enrollment on RP 'pam-access' restricted/,
        'checklist: enrollment restricted' );
  };

subtest 'empty --server-admin-rule is refused' => sub {
    my $dir = portal();
    my ( $rc, $out ) = autoconfig( $dir, '--server-admin-rule', ' ' );
    isnt( $rc, 0, 'non-zero exit' );
    like( $out, qr/must not be empty/, 'says why' );
    is( ( latest($dir) )[0], 1, 'nothing saved' );
};

subtest 'portal bootstrapped by an earlier version: enrollment closed' => sub {
    my $dir = portal( old_bootstrap() );
    my ( $rc, $out ) = autoconfig($dir);
    is( $rc, 0, 'exit 0' ) or diag $out;
    my ( undef, $c ) = latest($dir);

    is( $c->{oidcRPMetaDataOptions}{$RP}{$DA}, 0, 'open approval closed' );
    is_deeply(
        $c->{oidcRPMetaDataScopeRules}{$RP},
        { pam => '0', 'pam:server' => '0' },
        'open scope rules closed'
    );
    is( $c->{oidcRPMetaDataOptions}{$RP}{oidcRPMetaDataOptionsDisplayName},
        'PAM Access', 'rest of the RP kept' );
    ok( !exists $c->{pamAccessAllowedRps},
        'pamAccessAllowedRps not imposed on an existing deployment' );
    like( $out, qr/AllowDeviceAuthorization was 1, now 0/,
        'tightening reported without --verbose' );
    like( $out, qr/pamAccessAllowedRps is empty and the PAM RP already/,
        'missing allowlist reported' );
    like( $out, qr/\[RISK\] pamAccessAllowedRps is empty/,
        'checklist: allowlist at risk' );
};

subtest 'earlier version, re-run with --server-admin-rule' => sub {
    my $dir = portal( old_bootstrap() );
    my ( $rc, $out ) = autoconfig( $dir, '--server-admin-rule', $ADMIN );
    is( $rc, 0, 'exit 0' ) or diag $out;
    my ( undef, $c ) = latest($dir);
    is( $c->{oidcRPMetaDataOptions}{$RP}{$DA}, $ADMIN, 'approver rule set' );
    is_deeply(
        $c->{oidcRPMetaDataScopeRules}{$RP},
        { pam => $ADMIN, 'pam:server' => $ADMIN },
        'scope rules set'
    );

    # Closed RP (what this version writes), rule given later
    $dir = portal();
    autoconfig($dir);
    ( $rc, $out ) = autoconfig( $dir, '--server-admin-rule', $ADMIN );
    is( $rc, 0, 'closed RP, rule given: exit 0' ) or diag $out;
    ( undef, $c ) = latest($dir);
    is( $c->{oidcRPMetaDataOptions}{$RP}{$DA}, $ADMIN,
        'closed RP opened to the rule' );
    is( $c->{oidcRPMetaDataScopeRules}{$RP}{'pam:server'},
        $ADMIN, 'and its scope rules' );
};

subtest 'admin expressions are kept' => sub {
    my $old = old_bootstrap();
    $old->{oidcRPMetaDataOptions}{$RP}{$DA} = '$uid eq "root"';
    $old->{oidcRPMetaDataScopeRules}{$RP} =
      { pam => '1', 'pam:server' => '$uid eq "root"' };
    $old->{pamAccessAllowedRps} = "$RP, ob-bastion";
    my $dir = portal($old);
    my ( $rc, $out ) = autoconfig( $dir, '--server-admin-rule', $ADMIN );
    is( $rc, 0, 'exit 0' ) or diag $out;
    my ( undef, $c ) = latest($dir);
    is( $c->{oidcRPMetaDataOptions}{$RP}{$DA},
        '$uid eq "root"', 'approver expression kept' );
    is_deeply(
        $c->{oidcRPMetaDataScopeRules}{$RP},
        { pam => '1', 'pam:server' => '$uid eq "root"' },
        'scope rules untouched while the approver rule restricts'
    );
    is( $c->{pamAccessAllowedRps}, "$RP, ob-bastion", 'allowlist kept' );
};

subtest 'manager-saved empty allowlist on a new portal' => sub {
    my $dir = portal( { pamAccessAllowedRps => '', pamAccessRp => $RP } );
    my ( $rc, $out ) = autoconfig($dir);
    is( $rc, 0, 'exit 0' ) or diag $out;
    is( ( latest($dir) )[1]{pamAccessAllowedRps}, $RP, 'allowlist set' );
};

subtest '--force re-bootstraps an existing deployment' => sub {
    my $dir = portal( old_bootstrap() );
    my ( $rc, $out ) = autoconfig( $dir, '--force' );
    is( $rc, 0, 'exit 0' ) or diag $out;
    my ( undef, $c ) = latest($dir);
    is( $c->{oidcRPMetaDataOptions}{$RP}{$DA}, 0, 'enrollment closed' );
    is( $c->{pamAccessAllowedRps}, $RP, 'allowlist written' );
};

subtest '--dry-run saves nothing' => sub {
    my $dir = portal( old_bootstrap() );
    my ( $rc, $out ) = autoconfig( $dir, '--dry-run' );
    is( $rc, 0, 'exit 0' ) or diag $out;
    is( ( latest($dir) )[0], 1, 'nothing saved' );
    like( $out, qr/before production/, 'checklist still printed' );
};

subtest 'existing pamAccessRp differing from --rp-name: allowlist follows it' =>
  sub {
    my $dir = portal( { pamAccessRp => 'other-rp' } );
    my ( $rc, $out ) = autoconfig( $dir, '--rp-name', $RP );
    is( $rc, 0, 'exit 0' ) or diag $out;
    my ( undef, $c ) = latest($dir);
    is( $c->{pamAccessRp},         'other-rp', 'pamAccessRp kept' );
    is( $c->{pamAccessAllowedRps}, 'other-rp', 'allowlist = effective RP' );
  };

subtest 'padded placeholder values are trimmed' => sub {
    my $old = old_bootstrap();
    $old->{oidcRPMetaDataOptions}{$RP}{$DA} = '1 ';
    $old->{oidcRPMetaDataScopeRules}{$RP} =
      { pam => ' 1', 'pam:server' => ' 1 ' };
    my $dir = portal($old);
    my ( $rc, $out ) = autoconfig($dir);
    is( $rc, 0, 'exit 0' ) or diag $out;
    my ( undef, $c ) = latest($dir);
    is( $c->{oidcRPMetaDataOptions}{$RP}{$DA}, 0, '"1 " recognised as open' );
    is_deeply(
        $c->{oidcRPMetaDataScopeRules}{$RP},
        { pam => '0', 'pam:server' => '0' },
        'padded scope rules closed'
    );

    $old = old_bootstrap();
    $old->{oidcRPMetaDataOptions}{$RP}{$DA} = ' 0 ';
    $dir = portal($old);
    ( $rc, $out ) = autoconfig($dir);
    like( $out, qr/\[todo\] Server enrollment on RP 'pam-access' denies/,
        '" 0 " reported as closed' );
    autoconfig( $dir, '--server-admin-rule', $ADMIN );
    ( undef, $c ) = latest($dir);
    is( $c->{oidcRPMetaDataOptions}{$RP}{$DA},
        $ADMIN, '" 0 " is a placeholder' );
};

subtest '--server-admin-rule 1 warns only when written' => sub {
    my $old = old_bootstrap();
    $old->{oidcRPMetaDataOptions}{$RP}{$DA} = '$uid eq "root"';
    my ( $rc, $out ) = autoconfig( portal($old), '--server-admin-rule', '1' );
    unlike( $out, qr/lets ANY authenticated user/,
        'no warning: expression kept' );

    ( $rc, $out ) = autoconfig( portal(), '--server-admin-rule', '1' );
    like( $out, qr/lets ANY authenticated user/, 'warning: rule 1 written' );
};

done_testing();
