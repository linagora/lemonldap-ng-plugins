package MockUA;

use strict;
use warnings;
use Lemonldap::NG::Common::Conf;

# -------- interceptor state --------
our @REQUESTS;
our @RESPONSES;
our $HANDLER;

# -------- optional deps --------
our $DEPS_OK = 0;

eval {
    require LWP::Protocol::PSGI;
    require Plack::Request;
    require JSON;
    JSON->import(qw(to_json encode_json decode_json));

    # -------- PSGI app --------
    my $app = sub {
        my $env  = shift;
        my $preq = Plack::Request->new($env);

        my $body_raw = '';
        if ( $preq->content_length ) {
            $body_raw = $preq->content;
        }
        my $body;
        if ( $body_raw ne '' ) {
            eval { $body = decode_json($body_raw) };
        }

        my %headers;
        for my $h ( $preq->headers->header_field_names ) {
            $headers{$h} = $preq->headers->header($h);
        }

        push @MockUA::REQUESTS, {
            method  => $preq->method,
            path    => $preq->path_info,
            uri     => $preq->uri->as_string,
            headers => \%headers,
            body    => defined $body ? $body : $body_raw,
        };

        if ($MockUA::HANDLER) {
            my $res = $MockUA::HANDLER->($preq);
            return MockUA::_to_psgi($res);
        }

        my $resp = shift @MockUA::RESPONSES
          or return [ 500, [ 'Content-Type' => 'text/plain' ],
            ['MockUA: no canned response'] ];
        return MockUA::_to_psgi($resp);
    };

    LWP::Protocol::PSGI->register($app);
    $DEPS_OK = 1;
};

sub deps_ok { return $DEPS_OK }

sub reset {
    @REQUESTS  = ();
    @RESPONSES = ();
    undef $HANDLER;
}

# Each canned response is one of:
#   [$code, $hash_or_string]               - JSON-encoded body if hashref
#   [$code, $hash_or_string, \@headers]    - with extra headers
sub canned {
    my (@resps) = @_;
    push @RESPONSES, @resps;
}

sub handler {
    my ($sub) = @_;
    $HANDLER = $sub;
}

sub requests     { return @REQUESTS }
sub lastRequest  { return $REQUESTS[-1] }
sub requestCount { return scalar @REQUESTS }

sub _to_psgi {
    my ($r) = @_;
    my ( $code, $body, $extra_headers ) = @$r;
    my @headers = $extra_headers ? @$extra_headers : ();

    my $payload;
    if ( ref $body eq 'HASH' || ref $body eq 'ARRAY' ) {
        $payload = JSON::to_json($body);
        push @headers, 'Content-Type' => 'application/json'
          unless grep { lc $_ eq 'content-type' } @headers;
    }
    else {
        $payload = defined $body ? $body : '';
    }

    return [ $code, \@headers, [$payload] ];
}

# -------- backend factory --------
sub mockBackend {
    my (%params) = @_;
    MockUA::reset();

    my $backend = Lemonldap::NG::Common::Conf->new( {
        type         => 'OpenBAO',
        baseUrl      => 'https://bao.test/v1',
        token        => 't',
        mount        => 'secret',
        path         => 'lmConf',
        lockTtl      => 60,
        approleMount => 'approle',
        mdone        => 0,
        %params,
    } );
    die "Conf->new failed: $Lemonldap::NG::Common::Conf::msg"
      unless ref $backend;

    return $backend;
}

1;
