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

    unless ( $target->{audience} ) {
        $target->{rp} = $rp;
        return 1;
    }

    unless ( $target->{rp} ) {
        $self->logger->debug(
            "Token exchange request for an unexistent RP $target->{audience}");
        return 0;
    }

    return 1 if $target->{rp} eq $rp;

    my $list = $self->oidc->rpOptions->{ $target->{rp} }
      ->{oidcRPMetaDataOptionsTokenXAuthorizedMatrix};
    my $subject_issuer = $req->param('subject_issuer');
    unless ($subject_issuer) {
        $self->logger->debug('Request without subject_issuer');
        return 0;
    }
    unless ( $list and grep { $_ eq $subject_issuer } split /[,;\s]+/, $list ) {
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

    my $subject_issuer = $req->param('subject_issuer');
    $subject_issuer = $self->serverResolve($subject_issuer);

    # 2. Validate Matrix token against given Matrix server
    $self->logger->debug(
        "Token exchange asked for Matrix token $subjectToken on $subject_issuer"
    );

    my ( $matrixSub, $uid, $domain ) =
      $self->validateMatrixToken( $subject_issuer, $subjectToken );

    unless ($matrixSub) {
        $self->logger->debug("Matrix token rejected by $subject_issuer");
        return 0;
    }
    return $uid;
}

1;
