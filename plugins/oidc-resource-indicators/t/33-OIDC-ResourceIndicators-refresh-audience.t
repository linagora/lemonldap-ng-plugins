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
sub grant {
    my (@resources) = @_;
    my $query = join '&',
      buildForm( {
            response_type => 'code',
            scope         => 'openid offline_access',
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

# A resource outside the grant is either refused (invalid_target) or left out
# of the token; in no case does it reach `aud`.
sub no_audience {
    my ( $res, $forbidden, $name ) = @_;
    if ( $res->[0] != 200 ) {
        is( $res->[0], 400, "$name: refused" );
        my $json = from_json( $res->[2]->[0] );
        is( $json->{error}, 'invalid_target', "$name: invalid_target" );
        return;
    }
    my $json = from_json( $res->[2]->[0] );
    my @aud  = auds( id_token_payload( $json->{access_token} )->{aud} );
    ok( !( grep { $_ eq $forbidden } @aud ), "$name: not in the JWT aud" )
      or diag "aud: @aud";

    my $intro =
      from_json( introspect( $op, 'rpid', $json->{access_token} )->[2]->[0] );
    my @iaud = auds( $intro->{aud} );
    ok( !( grep { $_ eq $forbidden } @iaud ),
        "$name: not in the introspection aud" )
      or diag "introspection aud: @iaud";
}

subtest 'resource on the refresh alone adds nothing' => sub {
    my $t = grant();
    no_audience( refresh( $t->{refresh_token}, $API ),
        $API, 'never authorized' );
};

subtest 'resource wider than the authorization adds nothing' => sub {
    my $t = grant($API);
    no_audience( refresh( $t->{refresh_token}, $API, $API2 ),
        $API2, 'second RS' );
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
