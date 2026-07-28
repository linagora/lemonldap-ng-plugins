package Lemonldap::NG::Common::CustomFunctions;

use strict;
use warnings;
use Digest::SHA ();
use Net::CIDR   ();

our $VERSION = '0.1.0';

# Predefined UUID namespaces (RFC 9562, ex RFC 4122, appendix A)
our %NAMESPACES = (
    dns  => '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
    url  => '6ba7b811-9dad-11d1-80b4-00c04fd430c8',
    oid  => '6ba7b812-9dad-11d1-80b4-00c04fd430c8',
    x500 => '6ba7b814-9dad-11d1-80b4-00c04fd430c8',
);

# Default namespace used by uuid() when none is given
our $DEFAULT_NAMESPACE = 'url';

# Private IPv4 address space (RFC 1918)
our @PRIVATE_NETWORKS = ( '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16' );

## @cmethod array functions()
# List of the function names provided by this module, to be declared in the
# 'customFunctions' configuration parameter.
# @return list of short function names
sub functions {
    return qw(uuid isPrivateIp);
}

## @function string uuid(string value, string namespace)
# Compute a name-based UUID version 5 (SHA-1, RFC 9562) from a value. The
# same (value, namespace) pair always gives the same UUID, which makes it
# usable as a stable pseudonymous identifier for an application.
# @param $value value to hash (an empty string is used if undefined)
# @param $namespace namespace UUID, or one of 'dns', 'url', 'oid', 'x500'
#        (default: 'url')
# @return UUID in its canonical lowercase form
sub uuid {
    my ( $value, $namespace ) = @_;
    $value = '' unless defined $value;

    # UUID v5 hashes the UTF-8 encoded form of the name
    utf8::encode($value) if utf8::is_utf8($value);

    $namespace = $DEFAULT_NAMESPACE
      unless defined $namespace and length $namespace;
    my $ns = $NAMESPACES{ lc $namespace } || $namespace;

    ( my $ns_hex = lc $ns ) =~ s/^urn:uuid://;
    $ns_hex =~ s/[{}-]//g;
    die
"Lemonldap::NG::Common::CustomFunctions::uuid: invalid namespace '$namespace'\n"
      unless $ns_hex =~ /^[0-9a-f]{32}$/;

    my $ns_bin = pack 'H*', $ns_hex;
    my @b = unpack 'C*', substr( Digest::SHA::sha1( $ns_bin . $value ), 0, 16 );
    $b[6] = ( $b[6] & 0x0f ) | 0x50;    # version 5
    $b[8] = ( $b[8] & 0x3f ) | 0x80;    # RFC 9562 variant
    return sprintf
      '%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x',
      @b;
}

## @function boolean isPrivateIp(string ip, string network, ...)
# Check whether an IP address belongs to the private IPv4 address space
# (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Extra networks in
# CIDR notation can be given to widen the definition (loopback, IPv6 unique
# local addresses, an internal public range, ...).
# @param $ip IP address to test
# @param @others optional additional networks in CIDR notation
# @return 1 if the address is in one of the networks, 0 otherwise (including
#         when the address or one of the networks can't be parsed)
sub isPrivateIp {
    my ( $ip, @others ) = @_;
    return 0 unless defined $ip and length $ip;
    my $res = eval { Net::CIDR::cidrlookup( $ip, @PRIVATE_NETWORKS, @others ) };
    return $res ? 1 : 0;
}

1;
__END__

=head1 NAME

Lemonldap::NG::Common::CustomFunctions - extra functions for LemonLDAP::NG
rules, macros and headers

=head1 SYNOPSIS

In F</etc/lemonldap-ng/lemonldap-ng.ini>, on every portal and handler
evaluating the rules, macros or headers that use these functions:

  [all]
  require = /usr/share/perl5/Lemonldap/NG/Common/CustomFunctions.pm

In the Manager, C<General Parameters> » C<Advanced Parameters> »
C<Custom functions>:

  Lemonldap::NG::Common::CustomFunctions::uuid Lemonldap::NG::Common::CustomFunctions::isPrivateIp

Then, in a macro, a rule or a header:

  uuid($uid)
  uuid($uid, 'dns')
  uuid($uid, '2f4b1a10-1a2b-4c3d-8e5f-6a7b8c9d0e1f')
  isPrivateIp($ipAddr)
  isPrivateIp($ipAddr, '127.0.0.0/8', 'fc00::/7')

=head1 DESCRIPTION

LemonLDAP::NG shares a fixed set of functions with its Safe jail
(C<Lemonldap::NG::Common::Safelib>). This module provides additional ones,
declared through the C<customFunctions> configuration parameter.

Both functions are pure (no side effect, no access to the configuration or
to the session), so they are compatible with the
L<Safe jail|https://lemonldap-ng.org/documentation/latest/safejail.html>:
there is no need to disable it.

=head2 uuid($value, $namespace)

Returns the name-based UUID version 5 (SHA-1) of C<$value> in the given
namespace, in canonical lowercase form.

C<$namespace> accepts either one of the four predefined names C<dns>,
C<url> (default), C<oid> and C<x500>, or an explicit namespace UUID
(with or without dashes, C<urn:uuid:> prefix or curly braces). An invalid
namespace raises an exception rather than returning a constant value that
would be identical for every user.

C<$value> is hashed in its UTF-8 encoded form, so the result matches other
UUIDv5 implementations (Python C<uuid.uuid5>, C<Data::UUID::MT>, ...).

=head2 isPrivateIp($ip, @networks)

Returns 1 if C<$ip> belongs to the RFC 1918 private IPv4 address space,
0 otherwise. Additional networks in CIDR notation (IPv4 or IPv6) may be
given as extra arguments to extend that definition. An address (or a
network) that can't be parsed yields 0.

=head1 SEE ALSO

L<https://lemonldap-ng.org/documentation/latest/customfunctions.html>,
L<Lemonldap::NG::Common::Safelib>

=head1 AUTHOR

Xavier Guimard / Linagora L<https://linagora.com>

=head1 LICENSE AND COPYRIGHT

This library is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License version 2.

=cut
