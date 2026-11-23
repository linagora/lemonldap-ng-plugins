#!/usr/bin/perl

# Runs lemonldap-ng-store from the source tree for the tests: lib/ first,
# the LemonLDAP::NG stub last (only used when LLNG is not installed), and no
# manager rebuild (it would call the system llng-build-manager-files).

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";

BEGIN { push @INC, "$FindBin::Bin/../stub" }

require Lemonldap::NG::Common::Store;
{
    no warnings qw(redefine once);
    *Lemonldap::NG::Common::Store::Install::rebuildManager =
      sub { ( 1, 'manager rebuild skipped (tests)' ) };
}

Lemonldap::NG::Common::Store->run(@ARGV);
