package Lemonldap::NG::Common::Conf::Constants;

# Minimal stand-in used by the store tests when LemonLDAP::NG is not
# installed. It is appended to @INC, so the real module wins when present.

use strict;
use warnings;
use Exporter 'import';

use constant DEFAULTCONFFILE => '/etc/lemonldap-ng/lemonldap-ng.ini';
use constant DEFAULTSECTION  => 'all';

our @EXPORT_OK = qw(DEFAULTCONFFILE DEFAULTSECTION);

1;
