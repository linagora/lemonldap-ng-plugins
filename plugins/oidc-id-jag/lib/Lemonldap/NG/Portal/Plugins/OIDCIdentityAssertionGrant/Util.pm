package Lemonldap::NG::Portal::Plugins::OIDCIdentityAssertionGrant::Util;

use strict;
use Exporter qw(import);

our @EXPORT_OK = qw(numeric_date);

# RFC 7519 NumericDate: a finite number. Reject references, NaN, infinite
# values and anything that is not a plain decimal number (numeric strings are
# accepted for providers that already send them).
sub numeric_date {
    my ($value) = @_;
    return undef if ref $value;
    return undef unless defined $value;
    return undef
      unless $value =~
      /\A-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/;
    my $number = $value + 0;
    return undef unless $number - $number == 0;    # NaN or infinite
    return $number;
}

1;
