package Lemonldap::NG::Common::Matrix;

use strict;
use JSON;
use Lemonldap::NG::Common::FormEncode;
use Lemonldap::NG::Common::UserAgent;
use Mouse::Role;
use Net::DNS;
use Regexp::Common 'net';
use Regexp::Common::URI::RFC2396 '$hostname';

# Check IP:port or IP. Captures IP and port
my $isIpLiteral = qr/^($RE{net}{IPv6}|$RE{net}{IPv4})(?:(?<!:):(\d+))?$/;

# Check hostname:port or hostname. Cpatures hostname and port
my $isHostname = qr/^($hostname)(?:(?<!:):(\d+))?$/;

has ua => (
    is      => 'rw',
    lazy    => 1,
    builder => sub {

        # TODO : LWP options to use a proxy for example
        my $ua = Lemonldap::NG::Common::UserAgent->new( $_[0]->{conf} );
        $ua->env_proxy();
        return $ua;
    }
);

has dnsResolver => (
    is      => 'rw',
    lazy    => 1,
    builder => sub {
        return Net::DNS::Resolver->new;
    }
);

# MATRIX SERVER RESOLUTION
#
# main method: serverResolve

sub serverResolve {
    my ( $self, $name ) = @_;

    # From Matrix spec 1.9
    #
    # If the hostname is an IP literal, then that IP address should be used,
    # together with the given port number, or 8448 if no port is given.
    return "https://$1:" . ( $2 || '8448' ) . '/'
      if $name =~ $isIpLiteral;

    unless ( $name =~ $isHostname ) {
        $self->logger->error("Bad hostname $name");
        return;
    }

    # If the hostname is not an IP literal, and the server name includes an
    # explicit port, resolve the hostname to an IP address using CNAME, AAAA
    # or A records
    return "https://$1:$2/" if $2;

    # If the hostname is not an IP literal, a regular HTTPS request is made
    # to https://<hostname>/.well-known/matrix/server
    my $resp = $self->ua->get("https://$name/.well-known/matrix/server");
    if ( $resp->is_success ) {
        my $content = eval { JSON::from_json( $resp->decoded_content ) };
        unless ($@) {
            if (    ref($content)
                and ref($content) eq 'HASH'
                and my $delegated = $content->{'m.server'} )
            {
                # If <delegated_hostname> is an IP literal, then that IP
                # address should be used together with the <delegated_port>
                # or 8448 if no port is provided
                return "https://$1:" . ( $2 || '8448' ) . '/'
                  if $delegated =~ $isIpLiteral;

                unless ( $delegated =~ $isHostname ) {
                    $self->logger->error("Bad hostname $name");
                    return;
                }

                # If <delegated_hostname> is not an IP literal, and
                # <delegated_port> is present, an IP address is discovered by
                # looking up CNAME, AAAA or A records for <delegated_hostname>
                return "https://$1:$2/" if $2;

                # ALL NEXT CASES ARE EXACTLY THE SAME DNS SEARCH THAN IF NO
                # .well-known IS VALID BUT USING ${delegated} INSTEAD OF
                # ${name}

                # If <delegated_hostname> is not an IP literal and no
                # <delegated_port> is present, an SRV record is looked up for
                # _matrix-fed._tcp.<delegated_hostname>. This may result in
                # another hostname (to be resolved using AAAA or A records) and
                # port.
                #
                # [Deprecated] If <delegated_hostname> is not an IP literal, no
                # <delegated_port> is present, and a
                # _matrix-fed._tcp.<delegated_hostname> SRV record was not
                # found, an SRV record is looked up for
                # _matrix._tcp.<delegated_hostname>. This may result in another
                # hostname # (to be resolved using AAAA or A records) and port.
                #
                # If no SRV record is found, an IP address is resolved using
                # CNAME, # AAAA or A records. Requests are then made to the
                # resolve IP address # and a port of 8448, using a Host header
                # of <delegated_hostname>
                return $self->_dnsResolve($delegated);
            }
        }
    }
    return $self->_dnsResolve($name);
}

sub _dnsResolve {
    my ( $self, $name ) = @_;
    my @res;

    # If the /.well-known request resulted in an error response, a server is
    # found by resolving an SRV record for _matrix-fed._tcp.<hostname>. This
    # may result in a hostname (to be resolved using AAAA or A records) and
    # port
    @res = $self->dnsSrvResolve("_matrix-fed._tcp.$name");

    # [Deprecated] If the /.well-known request resulted in an error response,
    # and a _matrix-fed._tcp.<hostname> SRV record was not found, a server is
    # found by resolving an SRV record for _matrix._tcp.<hostname>
    @res = $self->dnsSrvResolve("_matrix._tcp.$name") unless @res;

    return ( wantarray ? @res : shift(@res) ) if @res;

    # If the /.well-known request returned an error response, and the
    # SRV record was not found, an IP address is resolved using CNAME,
    # AAAA and A records. Requests are made to the resolved IP address
    # using port 8448 and a Host header containing the <hostname>
    if ( rr($name) ) {
        return "https://$name:8448/";
    }
    else {
        $self->logger->error("Unable to resolve Matrix name $name");
        return;
    }
}

sub dnsSrvResolve {
    my ( $self, $name ) = @_;
    my $reply = $self->dnsResolver->query( $name, 'SRV' );
    return unless $reply;
    return map { 'https://' . $_->target . ':' . $_->port . '/' }
      sort { $b->priority <=> $a->priority } $reply->answer;
}

# MATRIX TOKEN VALIDATION
#
# main method: validateMatrixToken

sub validateMatrixToken {
    my ( $self, $matrixBaseUrl, $accessToken ) = @_;
    $matrixBaseUrl =~ s#/+$##;
    my $resp =
      $self->ua->get( "$matrixBaseUrl/_matrix/federation/v1/openid/userinfo?"
          . build_urlencoded( access_token => $accessToken ) );
    if ( $resp->is_success ) {
        my $content = eval { JSON::from_json( $resp->decoded_content ) };
        if ($@) {
            $self->logger->error("Bad response from $matrixBaseUrl: $@");
            return;
        }
        if ( ref $content eq 'HASH' and my $sub = $content->{sub} ) {
            unless ( $sub =~ /^\@(.*):(.*)$/ ) {
                $self->logger->error(
                    "Bad 'sub' received from $matrixBaseUrl: $sub");
                return;
            }
            return wantarray ? ( $sub, $1, $2 ) : $sub;
        }
        else {
            $self->logger->error(
                "Bad response from $matrixBaseUrl: " . $resp->decoded_content );
            return;
        }
    }
    else {
        $self->userLogger->error(
            "Token $accessToken refused by $matrixBaseUrl: "
              . $resp->status_line );
        return;
    }
}

1;
__END__

=head1 NAME

=encoding utf8

Lemonldap::NG::Common::Matrix - Library to interact with Matrix servers

=head1 SYNOPSIS

    use Mouse;
    with 'Lemonldap::NG::Common::Matrix';
    #
    # Server resolution
    #
    my $baseUrl = $self->serverResolve('matrix.org');
    # Gives: https://matrix-federation.matrix.org.cdn.cloudflare.net:8443/
    #
    # Token validation
    #
    my $subject = $self->validateMatrixToken( $baseUrl, 'federationToken' );
    # or
    my ( $subject, $username, $domain) =
        $self->validateMatrixToken( $baseUrl, 'federationToken' );
    # Gives the Matrix address of this user


=head1 DESCRIPTION

Lemonldap::NG::Common::Matrix is a L<Mouse::Role> that provides additional
methods to interact with Matrix servers.

=head1 METHODS

=head2 serverResolve

Return the base URL corresponding to the given Matrix "Servername", following
L<Matrix specifications|https://spec.matrix.org/v1.9/server-server-api/#server-discovery>

=head2 validateMatrixToken

Verify the given "federation token" and return the matrix address.

The "federation token" isn't the Matrix C<access_token> but a token that user
can get by calling C</_matrix/client/v3/user/$USER_ID/openid/request_token>
on its Matrix server.

=head1 SEE ALSO

L<Lemonldap::NG::Manager>, L<Lemonldap::NG::Portal>, L<Lemonldap::NG::Handler>

=head1 AUTHORS

=over

=item LemonLDAP::NG team L<http://lemonldap-ng.org/team>

=back

=head1 BUG REPORT

Use OW2 system to report bug or ask for features:
L<https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/issues>

=head1 DOWNLOAD

Lemonldap::NG is available at
L<https://lemonldap-ng.org/download>

=head1 COPYRIGHT AND LICENSE

See COPYING file for details.

This library is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see L<http://www.gnu.org/licenses/>.

=cut
