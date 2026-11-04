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
    my $list = $self->oidc->rpOptions->{ $target->{rp} }
      ->{oidcRPMetaDataOptionsTokenXAuthorizedMatrix};
    my $subject_issuer = $req->param('subject_issuer');
    unless ($subject_issuer) {
        $self->logger->debug('Request without subject_issuer');
        return 0;
    }
    unless ( $list
        and grep { lc($_) eq lc($subject_issuer) } split /[,;\s]+/, $list )
    {
        $self->logger->debug(
"Token exchange for an unauthorized Matrix server ($subject_issuer => $target->{rp})"
        );
        return 0;
    }
    return 1;
}

sub getUid {
    my ( $self, $req, $rp, $subjectToken, $subjectTokenType ) = @_;

    if ( $subjectTokenType and $subjectTokenType ne 'access_token' ) {
        $self->logger->debug(
            "Matrix given token isn't declared as access_token");
        return 0;
    }

    my $serverName     = $req->param('subject_issuer');
    my $subject_issuer = $self->serverResolve($serverName);
    unless ($subject_issuer) {
        $self->logger->debug("Unable to resolve Matrix server $serverName");
        return 0;
    }

    $self->logger->debug(
        "Token exchange asked for a Matrix token on $subject_issuer");

    my ( $matrixSub, $uid, $domain ) =
      $self->validateMatrixToken( $subject_issuer, $subjectToken );

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
    return $uid;
}

1;
