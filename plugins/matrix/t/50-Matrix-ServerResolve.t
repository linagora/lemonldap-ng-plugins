use strict;
use warnings;
use Test::More;
use JSON ();
use Mouse;

# Stubs for the role's ua, dnsResolver and logger

{
    package T::Logger;
    sub new     { bless {}, shift }
    sub error   { }
    sub warning { }
    sub debug   { }
}

{
    package T::Response;
    sub new {
        my ( $class, $code, $body ) = @_;
        return bless { code => $code, body => $body // '' }, $class;
    }
    sub is_success      { my $c = $_[0]->{code}; return $c >= 200 && $c < 300 }
    sub decoded_content { $_[0]->{body} }
}

{
    package T::UA;
    sub new {
        my ( $class, %urls ) = @_;
        return bless { urls => \%urls }, $class;
    }
    sub get {
        my ( $self, $url ) = @_;
        die "Unexpected request: $url" unless exists $self->{urls}{$url};
        return $self->{urls}{$url};
    }
}

{
    package T::RR;
    sub new   { my ( $class, %args ) = @_; return bless {%args}, $class }
    sub type  { $_[0]->{type} // 'SRV' }
    sub priority { $_[0]->{priority} // 0 }
    sub target { $_[0]->{target} }
    sub port   { $_[0]->{port} }
}

{
    package T::DNSReply;
    sub new    { my ( $class, @answers ) = @_; return bless { answer => \@answers }, $class }
    sub answer { @{ $_[0]->{answer} } }
}

{
    package T::DNS;
    sub new {
        my ( $class, %answers ) = @_;
        return bless { answers => \%answers }, $class;
    }
    sub query {
        my ( $self, $name, $type ) = @_;
        return T::DNSReply->new( @{ $self->{answers}{$name} // [] } );
    }
}

{
    package T::M;
    use Mouse;
    with 'Lemonldap::NG::Common::Matrix';

    has logger => ( is => 'ro', default => sub { T::Logger->new } );
}

sub matrix {
    my (%args) = @_;
    return T::M->new(
        ua          => $args{ua}  // T::UA->new,
        dnsResolver => $args{dns} // T::DNS->new,
    );
}

sub delegated {
    my ($value) = @_;
    return T::UA->new(
        'https://example.org/.well-known/matrix/server' => T::Response->new(
            200,
            JSON::to_json( { 'm.server' => $value } )
        ),
    );
}

my $m = matrix();

# IP literals
is( $m->serverResolve('1.2.3.4'), 'https://1.2.3.4:8448/',
    'IPv4 literal without port' );
is( $m->serverResolve('1.2.3.4:8448'), 'https://1.2.3.4:8448/',
    'IPv4 literal with port' );
is( $m->serverResolve('[::1]'), 'https://[::1]:8448/',
    'bracketed IPv6 literal without port' );
is( $m->serverResolve('[::1]:8448'), 'https://[::1]:8448/',
    'bracketed IPv6 literal with port' );
is( $m->serverResolve('[2001:db8::1]'), 'https://[2001:db8::1]:8448/',
    'bracketed IPv6 literal, no port' );
is( $m->serverResolve('[2001:db8::1]:1234'), 'https://[2001:db8::1]:1234/',
    'bracketed IPv6 literal, custom port' );

# Bare IPv6 literals are not valid Matrix server names (#113)
ok( !defined $m->serverResolve('::1'), 'bare IPv6 literal rejected' );
ok( !defined $m->serverResolve('2001:db8::1'),
    'bare IPv6 literal with hextets rejected' );

# Hostnames
is( $m->serverResolve('example.org:8448'), 'https://example.org:8448/',
    'hostname with port' );
is( $m->serverResolve('example.org:1'), 'https://example.org:1/',
    'lowest valid port' );
is( $m->serverResolve('example.org:65535'), 'https://example.org:65535/',
    'highest valid port' );

# Ports out of range are rejected (#114)
foreach my $name (
    'example.org:0',
    'example.org:65536',
    'example.org:99999999',
    '1.2.3.4:70000',
    '[::1]:0',
    '[::1]:65536'
  )
{
    ok( !defined $m->serverResolve($name), "$name rejected" );
}

# .well-known delegation
is(
    matrix( ua => delegated('example.org:1234') )
      ->serverResolve('example.org'),
    'https://example.org:1234/',
    'delegated hostname with port'
);
is(
    matrix( ua => delegated('[2001:db8::1]:1234') )
      ->serverResolve('example.org'),
    'https://[2001:db8::1]:1234/',
    'delegated bracketed IPv6 with port'
);
is(
    matrix( ua => delegated('[2001:db8::1]') )->serverResolve('example.org'),
    'https://[2001:db8::1]:8448/',
    'delegated bracketed IPv6 without port'
);
foreach my $value (
    '2001:db8::1',
    'example.org:0',
    'example.org:65536',
    'example.org:99999999',
    '1.2.3.4:70000'
  )
{
    ok( !defined matrix( ua => delegated($value) )->serverResolve('example.org'),
        "delegated $value rejected" );
}

# SRV records
my $dns = T::DNS->new(
    '_matrix-fed._tcp.example.org' => [
        T::RR->new( target => 'matrix.example.org.', port => 8448 ),
        T::RR->new( target => 'matrix2.example.org.', port => 70000 ),
        T::RR->new( target => '::1', port => 8448 ),
        T::RR->new( target => '.', port => 0 ),
    ],
);
is_deeply(
    [ matrix( dns => $dns )->dnsSrvResolve('_matrix-fed._tcp.example.org') ],
    ['https://matrix.example.org:8448/'],
    'only valid SRV targets and ports are kept'
);

$dns = T::DNS->new(
    '_matrix-fed._tcp.example.org' => [
        T::RR->new( target => '[2001:db8::1]', port => 8448 ),
    ],
);
is_deeply(
    [ matrix( dns => $dns )->dnsSrvResolve('_matrix-fed._tcp.example.org') ],
    ['https://[2001:db8::1]:8448/'],
    'bracketed IPv6 SRV target'
);

done_testing();
