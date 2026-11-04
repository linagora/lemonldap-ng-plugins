use warnings;
use Test::More;
use strict;
use IO::String;
use LWP::UserAgent;
use LWP::Protocol::PSGI;
use MIME::Base64;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my @contacted;

require Lemonldap::NG::Portal::UserDB::Demo;
$Lemonldap::NG::Portal::UserDB::Demo::demoAccounts{'french@evil.org'} = {
    uid  => 'french@evil.org',
    cn   => 'French from evil.org',
    mail => 'french@evil.org',
};

# m.org is the authorized Matrix server. evil.org is any other server: it
# vouches for whatever user its owner wants.
LWP::Protocol::PSGI->register(
    sub {
        my $req  = Plack::Request->new(@_);
        my $host = $req->env->{HTTP_HOST};
        push @contacted, $host;
        if ( $req->path_info eq '/_matrix/federation/v1/openid/userinfo' ) {
            my %subs = (
                'host.m.org' => {
                    'access_token=good'     => '@french:m.org',
                    'access_token=foreign'  => '@french:evil.org',
                    'access_token=mailish'  => '@french@evil.org:m.org',
                },
                'host.evil.org' => {
                    'access_token=evil' => '@french:evil.org',
                },
            );
            ( my $name = $host ) =~ s/:\d+$//;
            if ( my $sub = $subs{$name}->{ $req->query_string } ) {
                return [ 200, [], [ JSON::to_json( { sub => $sub } ) ] ];
            }
            return [ 403, [],
                ['{"errcode": "M_UNAUTHORIZED", "error": "Bad token"}'] ];
        }
        if ( $host =~ /^(m|evil)\.org/ ) {
            return [ 200, [],
                [ JSON::to_json( { 'm.server' => "host.$1.org:678" } ) ] ];
        }
        return [ 404, [], [] ];
    }
);

sub exchange {
    my ( $op, %params ) = @_;
    my $client = delete $params{client} // 'rpid';
    my $query  = buildForm( {
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

my $op = LLNG::Manager::Test->new( {
        ini => {
            domain                          => 'op.com',
            portal                          => 'http://auth.op.com',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            customPlugins                   => '::Plugins::MatrixTokenExchange',
            issuerDBOpenIDConnectActivation => 1,
            oidcRPMetaDataExportedVars => { rp => { name => "cn" } },
            oidcRPMetaDataOptions      => {
                rp => {
                    oidcRPMetaDataOptionsClientID     => "rpid",
                    oidcRPMetaDataOptionsClientSecret => "rpid",
                    oidcRPMetaDataOptionsAllowOffline => 1,
                    oidcRPMetaDataOptionsIDTokenSignAlg  => "HS512",
                    oidcRPMetaDataOptionsBypassConsent   => 1,
                    oidcRPMetaDataOptionsRedirectUris    => 'http://test/',
                    oidcRPMetaDataOptionsTokenXAuthorizedMatrix => 'm.org',
                },
                rp2 => {
                    oidcRPMetaDataOptionsClientID     => "rpid2",
                    oidcRPMetaDataOptionsClientSecret => "rpid2",
                    oidcRPMetaDataOptionsAllowOffline => 1,
                    oidcRPMetaDataOptionsIDTokenSignAlg  => "HS512",
                    oidcRPMetaDataOptionsBypassConsent   => 1,
                    oidcRPMetaDataOptionsRedirectUris    => 'http://test/',
                    oidcRPMetaDataOptionsTokenXAuthorizedRP => 'rp',
                },
                rp3 => {
                    oidcRPMetaDataOptionsClientID     => "rpid3",
                    oidcRPMetaDataOptionsClientSecret => "rpid3",
                    oidcRPMetaDataOptionsAllowOffline => 1,
                    oidcRPMetaDataOptionsIDTokenSignAlg  => "HS512",
                    oidcRPMetaDataOptionsBypassConsent   => 1,
                    oidcRPMetaDataOptionsRedirectUris    => 'http://test/',
                    oidcRPMetaDataOptionsTokenXAuthorizedMatrix => 'm.org',
                    oidcRPMetaDataOptionsTokenXAuthorizedRP     => 'rp2',
                },
                pub => {
                    oidcRPMetaDataOptionsClientID     => "pubid",
                    oidcRPMetaDataOptionsPublic       => 1,
                    oidcRPMetaDataOptionsAllowOffline => 1,
                    oidcRPMetaDataOptionsIDTokenSignAlg  => "HS512",
                    oidcRPMetaDataOptionsBypassConsent   => 1,
                    oidcRPMetaDataOptionsRedirectUris    => 'http://test/',
                    oidcRPMetaDataOptionsTokenXAuthorizedMatrix => 'm.org',
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);

my $res;

foreach my $audience ( 'rpid', undef ) {
    $res = exchange(
        $op,
        subject_token  => 'good',
        subject_issuer => 'm.org',
        ( $audience ? ( audience => $audience ) : () ),
    );
    my $json = expectJSON($res);
    ok( $json->{access_token},
        'Authorized server accepted (audience: ' . ( $audience // 'none' ) . ')' );
}

foreach my $audience ( 'rpid', undef ) {
    @contacted = ();
    $res       = exchange(
        $op,
        subject_token  => 'evil',
        subject_issuer => 'evil.org',
        ( $audience ? ( audience => $audience ) : () ),
    );
    expectReject( $res, 400 );
    ok( !( grep { /evil\.org/ } @contacted ),
            'Unauthorized server not contacted (audience: '
          . ( $audience // 'none' )
          . ')' );
}

# A request without subject_issuer is refused
$res = exchange( $op, subject_token => 'good', audience => 'rpid' );
expectReject( $res, 400 );

# An authorized server answering for a user of another server is refused:
# @french:evil.org is not @french:m.org
$res = exchange(
    $op,
    subject_token  => 'foreign',
    subject_issuer => 'm.org',
    audience       => 'rpid',
);
expectReject( $res, 400 );

# A localpart shaped like a mail address could reach a user of another domain
# once the user lookup also matches mail
$res = exchange(
    $op,
    subject_token  => 'mailish',
    subject_issuer => 'm.org',
);
expectReject( $res, 400 );

# An RP without allowlist accepts no server, whether it is the caller or the
# audience
$res = exchange(
    $op,
    client         => 'rpid2',
    subject_token  => 'good',
    subject_issuer => 'm.org',
);
expectReject( $res, 400 );
$res = exchange(
    $op,
    subject_token  => 'good',
    subject_issuer => 'm.org',
    audience       => 'rpid2',
);
expectReject( $res, 400 );

$res = exchange(
    $op,
    client         => 'rpid2',
    subject_token  => 'good',
    subject_issuer => 'm.org',
    audience       => 'rpid3',
);
ok( expectJSON($res)->{access_token},
    'Caller listed in the audience TokenXAuthorizedRP accepted' );

# An audience only accepts the callers it lists
foreach my $case ( [ 'rpid2', 'rpid' ], [ 'rpid', 'rpid3' ] ) {
    $res = exchange(
        $op,
        client         => $case->[0],
        subject_token  => 'good',
        subject_issuer => 'm.org',
        audience       => $case->[1],
    );
    expectReject( $res, 400 );
}

# A public RP is never a target: anyone holding the Matrix token could call it
$res = exchange(
    $op,
    client         => 'pubid',
    subject_token  => 'good',
    subject_issuer => 'm.org',
);
expectReject( $res, 400 );

clean_sessions();
done_testing();
