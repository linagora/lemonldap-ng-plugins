package Lemonldap::NG::Portal::Plugins::OIDCIdentityAssertionGrant::Util;

use strict;
use Exporter qw(import);

our @EXPORT_OK = qw(numeric_date ID_JAG_TYP RAR_SESSION_KEY);

# JOSE `typ` header of an ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant)
use constant ID_JAG_TYP => 'oauth-id-jag+jwt';

# Session key used by the oidc-rar plugin to carry RFC 9396 granted
# authorization_details across the code / refresh / access token sessions.
# Read-only coupling: no code dependency, and everything degrades to
# "no authorization_details" when oidc-rar is not installed.
use constant RAR_SESSION_KEY => '_rar_details';

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
