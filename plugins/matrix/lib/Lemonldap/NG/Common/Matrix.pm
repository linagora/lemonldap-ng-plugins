package Lemonldap::NG::Common::Matrix;

use strict;
use JSON;
use Lemonldap::NG::Common::FormEncode;
use Lemonldap::NG::Common::UserAgent;
use Mouse::Role;
use Net::DNS;
use Regexp::Common 'net';
use Regexp::Common::URI::RFC2396 '$hostname';

# Check [IPv6]:port, [IPv6], IPv4:port or IPv4. Captures IP and port.
# IPv6 literals must be bracketed, as required by the Matrix specification.
my $isIpLiteral = qr/^(\[$RE{net}{IPv6}\]|$RE{net}{IPv4})(?::(\d+))?$/;

# Check hostname:port or hostname. Captures hostname and port
my $isHostname = qr/^($hostname)(?::(\d+))?$/;

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

# Parse a Matrix server name. Return (host, port, is_ip_literal) or an empty
# list. Ports are checked here so that every caller rejects malformed names.
sub _parseServerName {
    my ( $self, $name ) = @_;

    my ( $host, $port, $isIp );
    if ( $name =~ $isIpLiteral ) {
        ( $host, $port, $isIp ) = ( $1, $2, 1 );
    }
    elsif ( $name =~ $isHostname ) {
        ( $host, $port, $isIp ) = ( $1, $2, 0 );
    }
    else {
        $self->logger->error("Bad hostname $name");
        return;
    }

    if ( defined $port and ( $port < 1 or $port > 65535 ) ) {
        $self->logger->error("Bad port in Matrix server name $name");
        return;
    }
    return ( $host, $port, $isIp );
}

# MATRIX SERVER RESOLUTION
#
# main method: serverResolve

sub serverResolve {
    my ( $self, $name, $ua ) = @_;
    $ua ||= $self->ua;

    my ( $host, $port, $isIp ) = $self->_parseServerName($name);
    return unless defined $host;

    # From Matrix spec 1.9
    #
    # If the hostname is an IP literal, then that IP address should be used,
    # together with the given port number, or 8448 if no port is given.
    return "https://$host:" . ( defined $port ? $port : '8448' ) . '/'
      if $isIp;

    # If the hostname is not an IP literal, and the server name includes an
    # explicit port, resolve the hostname to an IP address using CNAME, AAAA
    # or A records
    return "https://$host:$port/" if defined $port;

    # If the hostname is not an IP literal, a regular HTTPS request is made
    # to https://<hostname>/.well-known/matrix/server
    my $resp = $ua->get("https://$host/.well-known/matrix/server");
    if ( $resp->is_success ) {
        my $content = eval { JSON::from_json( $resp->decoded_content ) };
        unless ($@) {
            if ( ref($content) and ref($content) eq 'HASH' ) {
                my $delegated = $content->{'m.server'};
                if ( defined $delegated and !ref $delegated ) {
                    my ( $delegatedHost, $delegatedPort, $delegatedIsIp ) =
                      $self->_parseServerName($delegated);
                    return unless defined $delegatedHost;

                    # If <delegated_hostname> is an IP literal, then that IP
                    # address should be used together with the
                    # <delegated_port> or 8448 if no port is provided
                    return "https://$delegatedHost:"
                      . ( defined $delegatedPort ? $delegatedPort : '8448' )
                      . '/'
                      if $delegatedIsIp;

                    # If <delegated_hostname> is not an IP literal, and
                    # <delegated_port> is present, an IP address is discovered
                    # by looking up CNAME, AAAA or A records for
                    # <delegated_hostname>
                    return "https://$delegatedHost:$delegatedPort/"
                      if defined $delegatedPort;

                    # ALL NEXT CASES ARE EXACTLY THE SAME DNS SEARCH THAN IF
                    # NO .well-known IS VALID BUT USING ${delegatedHost}
                    # INSTEAD OF ${host}

                    # If <delegated_hostname> is not an IP literal and no
                    # <delegated_port> is present, an SRV record is looked up
                    # for _matrix-fed._tcp.<delegated_hostname>. This may
                    # result in another hostname (to be resolved using AAAA or
                    # A records) and port.
                    #
                    # [Deprecated] If <delegated_hostname> is not an IP
                    # literal, no <delegated_port> is present, and a
                    # _matrix-fed._tcp.<delegated_hostname> SRV record was not
                    # found, an SRV record is looked up for
                    # _matrix._tcp.<delegated_hostname>. This may result in
                    # another hostname # (to be resolved using AAAA or A
                    # records) and port.
                    #
                    # If no SRV record is found, an IP address is resolved
                    # using CNAME, # AAAA or A records. Requests are then made
                    # to the resolve IP address # and a port of 8448, using a
                    # Host header of <delegated_hostname>
                    return $self->_dnsResolve($delegatedHost);
                }
            }
        }
    }
    return $self->_dnsResolve($host);
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

    my @res;
    foreach my $rr (
        sort { $a->priority <=> $b->priority }
        grep { $_->type eq 'SRV' } $reply->answer
      )
    {
        my $target = $rr->target;
        my $port   = $rr->port;
        next unless defined $target and defined $port;
        next if $target eq '.';    # service not available

        # DNS returns fully qualified names
        $target =~ s/\.$//;

        # An SRV target has no port and no bracket syntax of its own. Reuse
        # the server name parser to reject impossible records and to bracket
        # IPv6 targets.
        my ($host) = $self->_parseServerName( $target . ':' . $port );
        next unless defined $host;

        push @res, "https://$host:$port/";
    }
    return @res;
}

# MATRIX TOKEN VALIDATION
#
# main method: validateMatrixToken

sub validateMatrixToken {
    my ( $self, $matrixBaseUrl, $accessToken, $ua ) = @_;
    $ua ||= $self->ua;
    $matrixBaseUrl =~ s#/+$##;
    my $resp =
      $ua->get( "$matrixBaseUrl/_matrix/federation/v1/openid/userinfo?"
          . build_urlencoded( access_token => $accessToken ) );
    if ( $resp->is_success ) {
        my $content = eval { JSON::from_json( $resp->decoded_content ) };
        if ($@) {
            $self->logger->error("Bad response from $matrixBaseUrl: $@");
            return;
        }
        if ( ref $content eq 'HASH' and my $sub = $content->{sub} ) {
            # Historical user ID grammar (printable ASCII localpart, no colon),
            # minus "@" so that a localpart never looks like a mail address
            unless ( $sub =~
                /^\@([\x21-\x39\x3B-\x3F\x41-\x7E]+):([A-Za-z0-9.\-:\[\]]+)\z/ )
            {
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
            "Matrix token refused by $matrixBaseUrl: "
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

IPv6 literals must be bracketed (C<[2001:db8::1]>), and an explicit port must
be between 1 and 65535. A malformed name is logged and returns C<undef>.

An optional second argument is the L<LWP::UserAgent> to use instead of C<ua>.

=head2 validateMatrixToken

Verify the given "federation token" and return the matrix address.

An optional third argument is the L<LWP::UserAgent> to use instead of C<ua>.

The "federation token" isn't the Matrix C<access_token> but a token that user
can get by calling C</_matrix/client/v3/user/$USER_ID/openid/request_token>
on its Matrix server.

=head1 SEE ALSO

L<Lemonldap::NG::Manager>, L<Lemonldap::NG::Portal>, L<Lemonldap::NG::Handler>

=head1 AUTHORS

=over

=item Xavier Guimard L<yadd@debian.org>

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
