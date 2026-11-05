package Lemonldap::NG::Portal::Plugins::MatrixTokenExchange;

use strict;
use Mouse;

extends 'Lemonldap::NG::Portal::Lib::OIDCTokenExchange';

with 'Lemonldap::NG::Common::Matrix';

sub validateAudience {
    my ( $self, $req, $rp, $target, $requestedTokenType ) = @_;

    if ( $requestedTokenType and $requestedTokenType ne 'access_token' ) {
        $self->logger->debug("Requested token isn't declared as access_token");
        return 0;
    }

    unless ( $target->{rp} ) {
        $self->logger->debug(
            "Token exchange request for an unexistent RP $target->{audience}");
        return 0;
    }

    # Matrix OpenID tokens are handed to widgets and integration managers, so
    # without a client secret anyone holding one could exchange it
    if ( $self->oidc->rpOptions->{ $target->{rp} }->{oidcRPMetaDataOptionsPublic} )
    {
        $self->logger->warn(
            "Matrix token exchange refused: $target->{rp} is a public client");
        return 0;
    }

    # Getting tokens for another RP needs that RP's consent, as in core
    # InternalTokenExchange
    if ( $target->{rp} ne $rp ) {
        my $callers = $self->oidc->rpOptions->{ $target->{rp} }
          ->{oidcRPMetaDataOptionsTokenXAuthorizedRP} // '';
        unless ( grep { $_ eq $rp } split /[,;\s]+/, $callers ) {
            $self->logger->debug(
                "Token exchange for an unauthorized RP ($rp => $target->{rp})");
            return 0;
        }
    }

    # Any Matrix server can vouch for any user it likes, so the allowlist is
    # checked on every request, and an empty allowlist authorizes no server
    my $opts = $self->oidc->rpOptions->{ $target->{rp} };
    my $list = $opts->{oidcRPMetaDataOptionsTokenXAuthorizedMatrix};
    my $mailMapping =
      ( $opts->{oidcRPMetaDataOptionsTokenXMatrixUser} // '' ) eq 'mail';
    my $subject_issuer = $req->param('subject_issuer');
    unless ($subject_issuer) {
        $self->logger->debug('Request without subject_issuer');
        return 0;
    }

    # A server name with a port or an IP literal is no mail domain
    if ( $mailMapping
        and $subject_issuer !~
        /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:[a-z]{2,}|xn--[a-z0-9-]+)\z/i )
    {
        $self->logger->debug(
            "Matrix server $subject_issuer is not a domain name");
        return 0;
    }

    my @servers = split /[,;\s]+/, $list // '';
    my $wildcard = grep { $_ eq '*' } @servers;
    if ( $wildcard and !$mailMapping and !$self->_wildcardWarned->{ $target->{rp} }++ )
    {
        $self->logger->warn( "\"*\" in TokenXAuthorizedMatrix of $target->{rp}"
              . ' is ignored unless TokenXMatrixUser is "mail"' );
    }

    # "*" is only safe when the user is looked up by its full address: each
    # server then only reaches the users of its own domain
    my $listed = grep { lc($_) eq lc($subject_issuer) } @servers;
    unless ( $listed or ( $wildcard and $mailMapping ) ) {
        $self->logger->debug(
"Token exchange for an unauthorized Matrix server ($subject_issuer => $target->{rp})"
        );
        return 0;
    }
    $req->data->{matrixMailMapping} = $mailMapping;

    # The internal allowlist is only for explicitly listed servers. A server
    # accepted through "*" is chosen by the caller; applying the allowlist to
    # it would let anyone reach an allowlisted internal IP from any domain.
    $req->data->{matrixInternalHosts} =
      $listed
      ? ( $opts->{oidcRPMetaDataOptionsTokenXMatrixInternalHosts} // '' )
      : '';
    return 1;
}

has _wildcardWarned => ( is => 'ro', default => sub { {} } );

# Every Matrix server, listed or accepted through "*", is chosen by the
# caller, and so are the hosts its .well-known, SRV target and redirects
# point to: resolve and fetch them with the paranoid agent, which refuses
# internal addresses at connect time.
has paranoidUa => (
    is      => 'rw',
    lazy    => 1,
    builder => sub {
        my $self = shift;
        require LWPx::ParanoidAgent;

        # LWPx::ParanoidAgent has no proxy support. ssl_opts is read by
        # LWPx::Protocol::https_paranoid, so a private CA configured through
        # lwpSslOpts still works; lwpOpts only contributes its timeout.
        my $lwpOpts = $self->conf->{lwpOpts} || {};
        my %opts    = (
            agent   => "LemonLDAP-NG/$Lemonldap::NG::Portal::Main::VERSION ",
            timeout => $lwpOpts->{timeout} || 10,
        );
        $opts{ssl_opts} = $self->conf->{lwpSslOpts}
          if $self->conf->{lwpSslOpts};
        my $ua = LWPx::ParanoidAgent->new(%opts);

        # Shared address space (RFC 6598), often used inside clusters
        $ua->blocked_hosts( qr/^100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./ );
        return $ua;
    }
);

has _internalHostsCache => ( is => 'ro', default => sub { {} } );

# Clone the paranoid agent and allow the RP's configured internal hosts.
# A hostname is resolved here so the private A records the agent will check
# are whitelisted too; whitelisting only the name would still block them.
sub _paranoidUa {
    my ( $self, $allowlist ) = @_;
    my @entries = grep { length } split /[,;\s]+/, $allowlist // '';
    return $self->paranoidUa unless @entries;

    my $ua = $self->paranoidUa->clone;
    $ua->whitelisted_hosts( $self->_internalWhitelist(@entries) );
    return $ua;
}

# Resolve the allowlist once and cache the result briefly: the agent rechecks
# every resolved IP, so a hostname must contribute both its name and its A
# records. Entries are IPv4 addresses or hostnames; IPv6 is not filtered by
# LWPx::ParanoidAgent, so it is logged and ignored.
sub _internalWhitelist {
    my ( $self, @entries ) = @_;
    my $key = join "\0", @entries;
    my $now = time;
    if ( my $cached = $self->_internalHostsCache->{$key} ) {
        return @{ $cached->{hosts} } if $now - $cached->{at} < 60;
    }

    my @whitelist;
    my $resolver = $self->paranoidUa->resolver;
    for my $entry (@entries) {
        if ( $entry =~ /^\[[0-9a-f:.]+\]$/i ) {
            $self->logger->warn(
"Matrix internal allowlist: IPv6 entry $entry ignored (only IPv4 is filtered)"
            );
            next;
        }
        push @whitelist, $entry;
        next if $entry =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;

        my $reply = $resolver->query( $entry, 'A' );
        my @addresses =
          $reply ? map { $_->address } grep { $_->type eq 'A' } $reply->answer
          : ();
        unless (@addresses) {
            $self->logger->warn(
                "Matrix internal allowlist: no A record for $entry");
            next;
        }
        push @whitelist, @addresses;
    }
    $self->_internalHostsCache->{$key} = { at => $now, hosts => \@whitelist };
    return @whitelist;
}

sub getUid {
    my ( $self, $req, $rp, $subjectToken, $subjectTokenType ) = @_;

    if ( $subjectTokenType and $subjectTokenType ne 'access_token' ) {
        $self->logger->debug(
            "Matrix given token isn't declared as access_token");
        return 0;
    }

    my $ua = $self->_paranoidUa( $req->data->{matrixInternalHosts} );
    my $serverName     = $req->param('subject_issuer');
    my $subject_issuer = $self->serverResolve( $serverName, $ua );
    unless ($subject_issuer) {
        $self->logger->debug("Unable to resolve Matrix server $serverName");
        return 0;
    }

    $self->logger->debug(
        "Token exchange asked for a Matrix token on $subject_issuer");

    my ( $matrixSub, $uid, $domain ) =
      $self->validateMatrixToken( $subject_issuer, $subjectToken, $ua );

    unless ($matrixSub) {
        $self->logger->debug("Matrix token rejected by $subject_issuer");
        return 0;
    }

    # A server is only trusted for its own users
    unless ( lc($domain) eq lc($serverName) ) {
        $self->userLogger->error(
            "Matrix server $serverName answered for foreign user $matrixSub");
        return 0;
    }
    return $req->data->{matrixMailMapping} ? "$uid\@" . lc($domain) : $uid;
}

1;
