use warnings;
use Test::More;
use strict;
use IO::String;
use MIME::Base64;
use JSON;
use URI::Escape ();

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my $API  = 'https://api.example.com';
my $API2 = 'https://api2.example.com';

sub rs {
    my ( $id, $identifier ) = @_;
    return {
        oidcRPMetaDataOptionsDisplayName     => $id,
        oidcRPMetaDataOptionsClientID        => $id,
        oidcRPMetaDataOptionsClientSecret    => $id,
        oidcRPMetaDataOptionsEnableRI        => 1,
        oidcRPMetaDataOptionsRIIdentifier    => $identifier,
        oidcRPMetaDataOptionsAccessTokenJWT  => 1,
        oidcRPMetaDataOptionsBypassConsent   => 1,
        oidcRPMetaDataOptionsRedirectUris    => "http://$id.example.com/",
        oidcRPMetaDataOptionsIDTokenSignAlg  => 'HS512',
    };
}

my $op = LLNG::Manager::Test->new( {
        ini => {
            domain                          => 'idp.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            customPlugins => '::Plugins::OIDCResourceIndicators',
            oidcServiceAllowOffline    => 1,
            oidcRPMetaDataExportedVars => {
                rp   => { name => 'cn' },
                api  => { name => 'cn' },
                api2 => { name => 'cn' },
            },
            oidcRPMetaDataOptions => {
                rp => {
                    oidcRPMetaDataOptionsDisplayName    => 'Client',
                    oidcRPMetaDataOptionsClientID       => 'rpid',
                    oidcRPMetaDataOptionsClientSecret   => 'rpid',
                    oidcRPMetaDataOptionsAccessTokenJWT => 1,
                    oidcRPMetaDataOptionsBypassConsent  => 1,
                    oidcRPMetaDataOptionsRedirectUris   => 'http://client.com/',
                    oidcRPMetaDataOptionsIDTokenSignAlg => 'HS512',
                    oidcRPMetaDataOptionsAllowOffline   => 1,
                    oidcRPMetaDataOptionsRefreshToken   => 1,
                    oidcRPMetaDataOptionsRefreshTokenRotation => 1,
                },
                api  => rs( 'api',  $API ),
                api2 => rs( 'api2', $API2 ),
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);
my $sid = login( $op, 'french' );

sub auds {
    my ($aud) = @_;
    return !defined $aud ? () : ref $aud eq 'ARRAY' ? @$aud : ($aud);
}

# Runs authorize + code grant with these resources, returns the token response
sub grant_with_scope {
    my ( $scope, @resources ) = @_;
    my $query = join '&',
      buildForm( {
            response_type => 'code',
            scope         => $scope,
            client_id     => 'rpid',
            state         => 's',
            redirect_uri  => 'http://client.com/',
        }
      ),
      map { 'resource=' . URI::Escape::uri_escape($_) } @resources;
    my $res = $op->_get(
        '/oauth2/authorize',
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$sid",
    );
    my ($code) = expectRedirection( $res, qr#http://.*code=([^\&]*)# );
    return expectJSON( codeGrant( $op, 'rpid', $code, 'http://client.com/' ) );
}

sub grant        { grant_with_scope( 'openid offline_access', @_ ) }
sub grant_online { grant_with_scope( 'openid',                @_ ) }

sub refresh {
    my ( $refresh_token, @resources ) = @_;
    my $query = join '&',
      buildForm( {
            grant_type    => 'refresh_token',
            refresh_token => $refresh_token,
        }
      ),
      map { 'resource=' . URI::Escape::uri_escape($_) } @resources;
    return $op->_post(
        '/oauth2/token',
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
        custom =>
          { HTTP_AUTHORIZATION => 'Basic ' . encode_base64( 'rpid:rpid', '' ) },
    );
}

# RFC 8707 section 2: a resource outside the grant is refused with
# invalid_target, and never reaches `aud`.
sub expect_invalid_target {
    my ( $res, $name ) = @_;
    is( $res->[0], 400, "$name: refused" );
    my $json = from_json( $res->[2]->[0] );
    is( $json->{error}, 'invalid_target', "$name: invalid_target" );
}

subtest 'resource on the refresh alone is refused' => sub {
    my $t = grant();
    expect_invalid_target( refresh( $t->{refresh_token}, $API ),
        'never authorized' );
};

subtest 'resource wider than the authorization is refused' => sub {
    my $t = grant($API);
    expect_invalid_target( refresh( $t->{refresh_token}, $API, $API2 ),
        'second RS' );
};

subtest 'a refused refresh does not consume the token (rotation)' => sub {
    my $t       = grant($API);
    my $refused = refresh( $t->{refresh_token}, $API2 );
    is( $refused->[0], 400, 'wider refresh refused' );

    # Rotation must not have removed the presented token before the refusal.
    my $again = refresh( $t->{refresh_token} );
    is( $again->[0], 200, 'the same refresh token still works' );
    my $json = from_json( $again->[2]->[0] );
    ok( $json->{refresh_token}, 'rotation issued a new refresh token' );
};

subtest 'online refresh: the same check applies' => sub {
    my $t = grant_online($API);
    ok( $t->{refresh_token}, 'online refresh token issued' );

    my $refused = refresh( $t->{refresh_token}, $API, $API2 );
    is( $refused->[0], 400, 'wider online refresh refused' );

    my $ok = refresh( $t->{refresh_token}, $API );
    is( $ok->[0], 200, 'narrower online refresh accepted' );
};

subtest 'a narrowed refresh does not shrink the grant' => sub {
    my $t     = grant( $API, $API2 );
    my $first = refresh( $t->{refresh_token}, $API );
    is( $first->[0], 200, 'narrowed refresh accepted' );
    my $json = from_json( $first->[2]->[0] );

    # RFC 8707: the refresh picks the audience of one token; it does not
    # remove the other resource from the grant.
    my $again = refresh( $json->{refresh_token}, $API2 );
    is( $again->[0], 200, 'the other resource is still allowed' );
    my @aud =
      auds( id_token_payload( from_json( $again->[2]->[0] )->{access_token} )
          ->{aud} );
    ok( ( grep { $_ eq $API2 } @aud ), 'other RS in aud' ) or diag "aud: @aud";
};

subtest 'a narrower resource stays possible' => sub {
    my $t   = grant( $API, $API2 );
    my $res = refresh( $t->{refresh_token}, $API );
    is( $res->[0], 200, 'refresh accepted' );
    my $json = from_json( $res->[2]->[0] );
    my @aud  = auds( id_token_payload( $json->{access_token} )->{aud} );
    ok( ( grep { $_ eq $API } @aud ), 'kept RS in aud' ) or diag "aud: @aud";
    ok( !( grep { $_ eq $API2 } @aud ), 'other RS not in aud' )
      or diag "aud: @aud";
};

clean_sessions();
done_testing();
