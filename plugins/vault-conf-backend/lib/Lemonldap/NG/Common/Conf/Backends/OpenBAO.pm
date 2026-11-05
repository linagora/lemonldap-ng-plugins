package Lemonldap::NG::Common::Conf::Backends::OpenBAO;

use strict;
use Scalar::Util qw(blessed);
use Lemonldap::NG::Common::UserAgent;
use Lemonldap::NG::Common::Conf::Constants;
use JSON qw(from_json to_json);
use HTTP::Request;

our $VERSION = '0.1.0';

BEGIN {
    *Lemonldap::NG::Common::Conf::ua       = \&ua;
    *Lemonldap::NG::Common::Conf::_req     = \&_req;
    *Lemonldap::NG::Common::Conf::_token   = \&_token;
    *Lemonldap::NG::Common::Conf::_login   = \&_login;
    *Lemonldap::NG::Common::Conf::_dataUrl = \&_dataUrl;
    *Lemonldap::NG::Common::Conf::_metaUrl = \&_metaUrl;
    *Lemonldap::NG::Common::Conf::_payload = \&_payload;
}

# Lifecycle state memoised on $self:
#   _token    : active X-Vault-Token
#   _tokenExp : epoch of AppRole token expiry (0 = never for static)
#   ua        : LWP::UserAgent instance

sub prereq {
    my $self = shift;

    unless ( $self->{baseUrl} ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "'baseUrl' is required in 'OpenBAO' configuration type\n";
        return 0;
    }

    my $hasToken  = defined $self->{token}    && $self->{token}    ne '';
    my $hasRole   = defined $self->{roleId}   && $self->{roleId}   ne '';
    my $hasSecret = defined $self->{secretId} && $self->{secretId} ne '';

    if ( $hasToken && ( $hasRole || $hasSecret ) ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: 'token' and 'roleId'/'secretId' are mutually exclusive\n";
        return 0;
    }
    unless ( $hasToken || ( $hasRole && $hasSecret ) ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: either 'token' or both 'roleId' and 'secretId' are required\n";
        return 0;
    }

    $self->{mount}       ||= 'secret';
    $self->{path}        ||= 'lmConf';
    $self->{lockTtl}     ||= 60;
    $self->{approleMount}||= 'approle';

    $self->{baseUrl} =~ s#/+$##;

    unless ( $self->{baseUrl} =~ m#/v[0-9]+$# ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: 'baseUrl' should end with /v<N> (e.g. /v1)\n";
    }

    return 1;
}

sub ua {
    my ($self) = @_;
    return $self->{ua} if $self->{ua};
    return $self->{ua} = Lemonldap::NG::Common::UserAgent->new(
        { lwpOpts => $self->{lwpOpts}, lwpSslOpts => $self->{lwpSslOpts} } );
}

sub _login {
    my $self = shift;
    my $url  = $self->{baseUrl} . '/auth/' . $self->{approleMount} . '/login';
    my $body = to_json(
        { role_id => $self->{roleId}, secret_id => $self->{secretId} } );
    my $req = HTTP::Request->new( 'POST', $url );
    $req->header( 'Content-Type' => 'application/json' );
    $req->content($body);
    my $resp = $self->ua->request($req);
    unless ( $resp->is_success ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO AppRole login failed: " . $resp->status_line . "\n";
        return;
    }
    my $data;
    eval { $data = from_json( $resp->content, { allow_nonref => 1 } ) };
    if ( $@
        || ref $data ne 'HASH'
        || ref $data->{auth} ne 'HASH'
        || !defined $data->{auth}{client_token}
        || ref $data->{auth}{client_token}
        || $data->{auth}{client_token} eq '' )
    {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO AppRole login: unexpected response\n";
        return;
    }

    my $lease = $data->{auth}{lease_duration};
    $lease = _isUint($lease) ? $lease : 0;

    $self->{_token}    = $data->{auth}{client_token};
    $self->{_tokenExp} = time + $lease;
}

sub _token {
    my $self = shift;
    if ( $self->{roleId} ) {
        if ( !$self->{_token} || $self->{_tokenExp} - time < 30 ) {
            $self->_login();
        }
        return $self->{_token};
    }
    return $self->{token};
}

sub _req {
    my ( $self, $method, $url, $body ) = @_;

    my $token = $self->_token;
    unless ($token) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: no valid token available\n";
        return undef;
    }

    my $attempt = 0;
    while ( $attempt < 2 ) {
        my $req = HTTP::Request->new( $method, $url );
        $req->header( 'X-Vault-Token' => $token );
        $req->header( 'X-Vault-Namespace' => $self->{namespace} )
          if $self->{namespace};
        if ( defined $body ) {
            $req->header( 'Content-Type' => 'application/json' );
            $req->content( to_json( $body, { allow_nonref => 1 } ) );
        }

        my $resp = $self->ua->request($req);
        my $code = $resp->code;

        if ( !$resp->is_success && ( !$code || $code >= 500 ) ) {
            $attempt++;
            if ( $attempt < 2 ) {
                select( undef, undef, undef, 0.2 );
                next;
            }
            $Lemonldap::NG::Common::Conf::msg .=
              "OpenBAO request failed ($method $url): " . $resp->status_line . "\n";
            return undef;
        }

        # Non-5xx failure — return raw response for caller to inspect
        if ( !$resp->is_success ) {
            return $resp;
        }

        my $content = $resp->content;
        return {} unless defined $content && $content ne '';

        my $data;
        eval { $data = from_json( $content, { allow_nonref => 1 } ) };
        if ($@) {
            $Lemonldap::NG::Common::Conf::msg .=
              "OpenBAO: JSON decode error for $url: $@\n";
            return undef;
        }
        return $data;
    }
    return undef;
}

sub _dataUrl {
    my ( $self, $name ) = @_;
    return $self->{baseUrl} . '/' . $self->{mount} . '/data/'
      . $self->{path} . '/' . $name;
}

sub _metaUrl {
    my ( $self, $name ) = @_;
    return $self->{baseUrl} . '/' . $self->{mount} . '/metadata/'
      . $self->{path} . '/' . $name;
}

sub _payload {
    my ( $self, $resp ) = @_;
    unless ( ref $resp eq 'HASH'
        && ref $resp->{data} eq 'HASH'
        && ref $resp->{data}{data} eq 'HASH' )
    {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: unexpected data payload\n";
        return;
    }
    return $resp->{data}{data};
}

sub _isUint {
    my ($value) = @_;
    return defined $value
      && !ref $value
      && $value =~ /\A[0-9]+\z/;
}

sub store {
    my ( $self, $fields ) = @_;
    my $cfgNum = ref $fields eq 'HASH' ? $fields->{cfgNum} : undef;
    unless ( _isUint($cfgNum) ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: invalid configuration number\n";
        return UNKNOWN_ERROR;
    }
    my $url = $self->_dataUrl("lmConf-$cfgNum");
    my $result = $self->_req( 'POST', $url,
        { options => { cas => 0 }, data => $fields } );

    unless ( defined $result ) {
        $self->unlock();
        return UNKNOWN_ERROR;
    }

    if ( ref $result && blessed($result) && $result->isa('HTTP::Response') ) {
        my $code = $result->code;
        if ( $code == 403 ) {
            $self->unlock();
            return UPLOAD_DENIED;
        }
        if ( $code == 400 ) {
            my $body;
            eval {
                $body = from_json( $result->content, { allow_nonref => 1 } );
            };
            if ( !$@
                && ref $body eq 'HASH'
                && ref $body->{errors} eq 'ARRAY'
                && grep { /check-and-set/i } @{ $body->{errors} } )
            {
                $self->unlock();
                return CONFIG_WAS_CHANGED;
            }
            $self->unlock();
            return UNKNOWN_ERROR;
        }
        $self->unlock();
        return UNKNOWN_ERROR;
    }

    return $cfgNum;
}

sub load {
    my ( $self, $cfgNum ) = @_;
    unless ( _isUint($cfgNum) ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: invalid configuration number\n";
        return undef;
    }
    my $url    = $self->_dataUrl("lmConf-$cfgNum");
    my $result = $self->_req( 'GET', $url );

    return undef unless defined $result;

    if ( ref $result && blessed($result) && $result->isa('HTTP::Response') ) {
        if ( $result->code == 404 ) {
            return undef;
        }
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: load lmConf-$cfgNum failed: " . $result->status_line . "\n";
        return undef;
    }

    return $self->_payload($result);
}

sub available {
    my $self   = shift;
    my $url    = $self->_metaUrl('');
    my $result = $self->_req( 'LIST', $url );

    return () unless defined $result;

    if ( ref $result && blessed($result) && $result->isa('HTTP::Response') ) {
        return () if $result->code == 404;
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: LIST failed: " . $result->status_line . "\n";
        return ();
    }

    unless ( ref $result eq 'HASH'
        && ref $result->{data} eq 'HASH'
        && ref $result->{data}{keys} eq 'ARRAY' )
    {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: LIST returned an unexpected payload\n";
        return ();
    }

    my $keys = $result->{data}{keys};
    return sort { $a <=> $b }
      map {    defined $_ && !ref $_
          && $_ =~ /^lmConf-(\d+)$/ ? ($1) : () } @$keys;
}

sub lastCfg {
    my $self  = shift;
    my @avail = $self->available;
    return $avail[$#avail];
}

sub delete {
    my ( $self, $cfgNum ) = @_;
    unless ( _isUint($cfgNum) ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: invalid configuration number\n";
        return 0;
    }
    my $url    = $self->_metaUrl("lmConf-$cfgNum");
    my $result = $self->_req( 'DELETE', $url );

    unless ( defined $result ) {
        return 0;
    }

    if ( ref $result && blessed($result) && $result->isa('HTTP::Response') ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: delete lmConf-$cfgNum failed: " . $result->status_line . "\n";
        return 0;
    }

    return 1;
}

sub lock {
    my $self      = shift;
    my $url       = $self->_dataUrl("lmConf.lock");
    my $expiresAt = time + $self->{lockTtl};
    my $body      = {
        options => { cas => 0 },
        data    => { pid => $$, expiresAt => $expiresAt },
    };

    my $result = $self->_req( 'POST', $url, $body );

    if ( defined $result && !( ref $result && blessed($result) && $result->isa('HTTP::Response') ) )
    {
        return 1;
    }

    unless ( defined $result ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: lock acquisition failed (transport)\n";
        return 0;
    }

    my $code = $result->code;
    if ( $code == 400 ) {
        my $get = $self->_req( 'GET', $url );

        if ( ref $get && blessed($get) && $get->isa('HTTP::Response') && $get->code == 404 ) {

            # Why: lock was released between our POST and GET — retry once
            my $result2 = $self->_req( 'POST', $url, $body );
            if ( defined $result2
                && !( ref $result2 && blessed($result2) && $result2->isa('HTTP::Response') ) )
            {
                return 1;
            }
            $Lemonldap::NG::Common::Conf::msg .=
              "OpenBAO: lock retry after release failed\n";
            return 0;
        }

        if ( defined $get
            && !( ref $get && blessed($get) && $get->isa('HTTP::Response') ) )
        {
            my $current = $self->_payload($get);
            unless ($current) {
                $Lemonldap::NG::Common::Conf::msg .=
                  "OpenBAO: could not read existing lock\n";
                return 0;
            }

            my $currentExpires = $current->{expiresAt};
            unless ( _isUint($currentExpires) ) {
                $Lemonldap::NG::Common::Conf::msg .=
                  "OpenBAO: existing lock has no valid expiration\n";
                return 0;
            }

            my $metadata = $get->{data}{metadata};
            my $currentVersion =
              ref $metadata eq 'HASH'
              && _isUint( $metadata->{version} )
              ? $metadata->{version}
              : undef;
            unless ( defined $currentVersion ) {
                $Lemonldap::NG::Common::Conf::msg .=
                  "OpenBAO: existing lock has no valid version\n";
                return 0;
            }

            if ( $currentExpires > time ) {
                $Lemonldap::NG::Common::Conf::msg .=
                  "OpenBAO: Lock held until $currentExpires\n";
                return 0;
            }

            my $stealBody = {
                options => { cas => $currentVersion },
                data    => { pid => $$, expiresAt => $expiresAt },
            };
            my $result2 = $self->_req( 'POST', $url, $stealBody );
            if ( defined $result2
                && !( ref $result2 && blessed($result2) && $result2->isa('HTTP::Response') ) )
            {
                return 1;
            }
            if ( ref $result2
                && blessed($result2) && $result2->isa('HTTP::Response')
                && $result2->code == 400 )
            {
                $Lemonldap::NG::Common::Conf::msg .=
                  "OpenBAO: Lost lock-steal race\n";
                return 0;
            }
            $Lemonldap::NG::Common::Conf::msg .=
              "OpenBAO: lock steal failed\n";
            return 0;
        }

        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: could not read existing lock\n";
        return 0;
    }

    $Lemonldap::NG::Common::Conf::msg .=
      "OpenBAO: lock failed: " . $result->status_line . "\n";
    return 0;
}

sub unlock {
    my $self   = shift;
    my $url    = $self->_metaUrl("lmConf.lock");
    my $result = $self->_req( 'DELETE', $url );

    unless ( defined $result ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: unlock transport failure\n";
        return 1;
    }

    if ( ref $result && blessed($result) && $result->isa('HTTP::Response') ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: unlock failed: " . $result->status_line . "\n";
    }

    return 1;
}

sub isLocked {
    my $self   = shift;
    my $url    = $self->_dataUrl("lmConf.lock");
    my $result = $self->_req( 'GET', $url );

    unless ( defined $result ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: could not read lock state\n";
        return 1;
    }

    if ( ref $result && blessed($result) && $result->isa('HTTP::Response') ) {
        return 0 if $result->code == 404;
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: could not read lock state: " . $result->status_line . "\n";
        return 1;
    }

    my $payload = $self->_payload($result);
    return 1 unless $payload;

    my $expiresAt = $payload->{expiresAt};
    unless ( _isUint($expiresAt) ) {
        $Lemonldap::NG::Common::Conf::msg .=
          "OpenBAO: lock has no valid expiration\n";
        return 1;
    }

    return $expiresAt < time ? 0 : 1;
}

1;
__END__
