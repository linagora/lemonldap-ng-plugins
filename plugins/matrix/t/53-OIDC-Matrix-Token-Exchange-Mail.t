use warnings;
use Test::More;
use strict;
use IO::String;
use LWP::UserAgent;
use LWP::Protocol::PSGI;
use HTTP::Message::PSGI qw(req_to_psgi res_from_psgi);
use MIME::Base64;
use Net::DNS;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

# Only the full address exists, so a success proves the mail lookup
require Lemonldap::NG::Portal::UserDB::Demo;
$Lemonldap::NG::Portal::UserDB::Demo::demoAccounts{'alice@m.org'} = {
    uid  => 'alice@m.org',
    cn   => 'Alice',
    mail => 'alice@m.org',
};

$Lemonldap::NG::Portal::UserDB::Demo::demoAccounts{'alice@int.org'} = {
    uid  => 'alice@int.org',
    cn   => 'Alice Int',
    mail => 'alice@int.org',
};

# evil.org must not reach bob through its own @bob:evil.org
$Lemonldap::NG::Portal::UserDB::Demo::demoAccounts{bob} = {
    uid  => 'bob',
    cn   => 'Bob',
    mail => 'bob@m.org',
};

# Each e<n>.org delegates to an internal target
my %delegation = (
    'm.org'    => 'host.m.org:678',
    'evil.org' => 'host.evil.org:678',
    'e1.org'   => '10.0.0.5:8080',
    'e2.org'   => 'internal.e2.org:443',
    'e3.org'   => 'cgnat.e3.org:443',
    'e5.org'   => '[::1]:8448',
    'int.org'  => 'host.int.org:8080',
);
my %dns = (
    ( map { $_ => '198.51.100.1' } qw(m.org host.m.org evil.org host.evil.org) ),
    ( map { $_ => '198.51.100.2' } qw(e1.org e2.org e3.org e5.org int.org) ),
    'internal.e2.org' => '10.0.0.5',
    'host.int.org'    => '10.0.0.5',
    'cgnat.e3.org'    => '100.64.1.1',
    'e4.org'          => '127.0.0.1',
);

my @contacted;
my $app = sub {
    my $req  = Plack::Request->new(@_);
    my $host = $req->env->{HTTP_HOST};
    push @contacted, $host;
    ( my $name = $host ) =~ s/:\d+$//;
    if ( $req->path_info eq '/_matrix/federation/v1/openid/userinfo' ) {
        my %subs = (
            'host.m.org'    => { 'access_token=alice' => '@alice:m.org' },
            'host.int.org'  => { 'access_token=alice' => '@alice:int.org' },
            'host.evil.org' => {
                'access_token=alice' => '@alice:m.org',
                'access_token=bob'   => '@bob:evil.org',
            },
        );
        if ( my $sub = $subs{$name}->{ $req->query_string } ) {
            return [ 200, [], [ JSON::to_json( { sub => $sub } ) ] ];
        }
        return [ 403, [],
            ['{"errcode": "M_UNAUTHORIZED", "error": "Bad token"}'] ];
    }
    if ( my $target = $delegation{$name} ) {
        return [ 200, [], [ JSON::to_json( { 'm.server' => $target } ) ] ];
    }
    return [ 404, [], [] ];
};
LWP::Protocol::PSGI->register($app);

# LWPx::ParanoidAgent resolves and checks the host itself before connecting:
# keep that part, and answer from $app instead of opening a socket
{

    package MockResolver;
    our @ISA = ('Net::DNS::Resolver');
    sub new    { bless {}, shift }
    sub bgsend { $_[0]->{q} = $_[1]; 'MOCK' }

    sub bgread {
        my $name   = $_[0]->{q};
        my $packet = Net::DNS::Packet->new($name);
        $packet->push( answer => Net::DNS::RR->new("$name 60 A $dns{$name}") )
          if $dns{$name};
        return $packet;
    }

    sub query {
        my ( $self, $name, $type ) = @_;
        my $packet = Net::DNS::Packet->new($name);
        $packet->push( answer => Net::DNS::RR->new("$name 60 A $dns{$name}") )
          if $dns{$name} and ( $type // 'A' ) eq 'A';
        return $packet;
    }

    package main;
    require LWPx::Protocol::https_paranoid;
    no warnings qw(redefine once);
    *LWPx::Protocol::https_paranoid::request = sub {
        my ( $self, $request ) = @_;
        $self->{ua}->_resolve( $request->uri->host, $request )
          or die "No suitable addresses found";
        my $env = req_to_psgi($request);
        $env->{HTTP_HOST} = $request->uri->host_port;
        my $res = res_from_psgi( $app->($env) );
        $res->request($request);
        return $res;
    };
}

sub exchange {
    my ( $op, $client, %params ) = @_;
    my $query = buildForm( {
            grant_type => 'urn:ietf:params:oauth:grant-type:token-exchange',
            client_id  => $client,
            scope      => 'openid profile email',
            %params,
        }
    );
    return $op->_post(
        '/oauth2/token', IO::String->new($query),
        accept => 'application/json',
        length => length($query),
        custom => {
            HTTP_AUTHORIZATION => "Basic " . encode_base64("$client:$client"),
        }
    );
}

sub rp {
    my ( $id, %opts ) = @_;
    return {
        oidcRPMetaDataOptionsClientID       => $id,
        oidcRPMetaDataOptionsClientSecret   => $id,
        oidcRPMetaDataOptionsAllowOffline   => 1,
        oidcRPMetaDataOptionsIDTokenSignAlg => "HS512",
        oidcRPMetaDataOptionsBypassConsent  => 1,
        oidcRPMetaDataOptionsRedirectUris   => 'http://test/',
        oidcRPMetaDataOptionsTokenXAuthorizedMatrix => '*',
        %opts,
    };
}

my $op = LLNG::Manager::Test->new( {
        ini => {
            domain                          => 'op.com',
            portal                          => 'http://auth.op.com',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            lwpSslOpts                      => { SSL_verify_mode => 0 },
            customPlugins                   => '::Plugins::MatrixTokenExchange',
            issuerDBOpenIDConnectActivation => 1,
            oidcRPMetaDataExportedVars      => {
                mail      => { name => "cn" },
                listed    => { name => "cn" },
                localpart => { name => "cn" },
                allow     => { mail => { name => "cn" } },
                wildallow => { mail => { name => "cn" } },
            },
            oidcRPMetaDataOptions => {
                mail => rp(
                    'mailrp', oidcRPMetaDataOptionsTokenXMatrixUser => 'mail'
                ),
                listed => rp(
                    'listedrp',
                    oidcRPMetaDataOptionsTokenXMatrixUser       => 'mail',
                    oidcRPMetaDataOptionsTokenXAuthorizedMatrix =>
                      'm.org,int.org',
                ),
                allow => rp(
                    'allowrp',
                    oidcRPMetaDataOptionsTokenXMatrixUser       => 'mail',
                    oidcRPMetaDataOptionsTokenXAuthorizedMatrix => 'int.org',
                    oidcRPMetaDataOptionsTokenXMatrixInternalHosts =>
                      'host.int.org',
                ),
                wildallow => rp(
                    'wildallowrp',
                    oidcRPMetaDataOptionsTokenXMatrixUser       => 'mail',
                    oidcRPMetaDataOptionsTokenXAuthorizedMatrix => '*',
                    oidcRPMetaDataOptionsTokenXMatrixInternalHosts =>
                      'host.int.org',
                ),
                localpart => rp('localrp'),
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);
my $resolver = MockResolver->new;
my $plugin =
  $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::MatrixTokenExchange'};
$plugin->paranoidUa->resolver($resolver);
$plugin->dnsResolver($resolver);
is( $plugin->paranoidUa->{ssl_opts}->{SSL_verify_mode}, 0,
    'lwpSslOpts is passed to the paranoid agent' );

foreach my $client (qw(mailrp listedrp)) {
    my $res = exchange(
        $op, $client,
        subject_token  => 'alice',
        subject_issuer => 'm.org',
    );
    ok( expectJSON($res)->{access_token},
        "$client: \@alice:m.org found as alice\@m.org" );
}

# A server answering for another domain is refused, even with "*"
my $res = exchange(
    $op, 'mailrp',
    subject_token  => 'alice',
    subject_issuer => 'evil.org',
);
expectReject( $res, 400 );

# A server answering for its own user only reaches that user's address
$res = exchange(
    $op, 'mailrp',
    subject_token  => 'bob',
    subject_issuer => 'evil.org',
);
expectReject( $res, 400 );

# With "*", a port or an IP literal never makes the portal query that host
foreach my $issuer ( '10.0.0.5:8080', '[::1]', 'm.org:678', "m.org\n" ) {
    @contacted = ();
    $res       = exchange(
        $op, 'mailrp',
        subject_token  => 'alice',
        subject_issuer => $issuer,
    );
    expectReject( $res, 400 );
    ok( !@contacted, "$issuer not contacted" );
}

# Nor does a server delegating to, or resolving to, an internal address
foreach my $issuer (qw(e1.org e2.org e3.org e4.org e5.org)) {
    @contacted = ();
    $res       = exchange(
        $op, 'mailrp',
        subject_token  => 'alice',
        subject_issuer => $issuer,
    );
    expectReject( $res, 400 );
    ok( !( grep { !/^e\d\.org:443$/ } @contacted ),
        "$issuer: only its own .well-known contacted" )
      or explain \@contacted;
}

# A listed server is filtered too: its delegation to an internal target
# is refused unless the RP allowlists that target.
@contacted = ();
$res = exchange(
    $op, 'listedrp',
    subject_token  => 'alice',
    subject_issuer => 'int.org',
);
expectReject( $res, 400 );
ok( !( grep { !/^int\.org:443$/ } @contacted ),
    'listed server: internal delegation not contacted' )
  or explain \@contacted;

# The RP allowlist lets the same delegation through.
@contacted = ();
$res = exchange(
    $op, 'allowrp',
    subject_token  => 'alice',
    subject_issuer => 'int.org',
);
ok( expectJSON($res)->{access_token},
    'allowlisted internal target accepted' );
ok( ( grep { /^host\.int\.org:8080$/ } @contacted ),
    'allowlisted internal target contacted' )
  or explain \@contacted;

# The allowlist is ignored for a server accepted through "*": the caller
# chooses the server, so it must stay fully paranoid.
@contacted = ();
$res = exchange(
    $op, 'wildallowrp',
    subject_token  => 'alice',
    subject_issuer => 'int.org',
);
expectReject( $res, 400 );
ok( !( grep { !/^int\.org:443$/ } @contacted ),
    'wildcard + allowlist: internal delegation not contacted' )
  or explain \@contacted;

# "*" authorizes no server when users are looked up by localpart
$res = exchange(
    $op, 'localrp',
    subject_token  => 'alice',
    subject_issuer => 'm.org',
);
expectReject( $res, 400 );

clean_sessions();
done_testing();
