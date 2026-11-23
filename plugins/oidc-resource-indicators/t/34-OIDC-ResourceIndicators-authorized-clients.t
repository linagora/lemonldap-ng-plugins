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

# A resource server decides which clients may get a token bound to it
# (oidcRPMetaDataOptionsRIAuthorizedRP, empty = none) and its access rule
# must accept the subject of the token.

my $API     = 'https://api.example.com';
my $M2M     = 'https://m2m.example.com';
my $CLOSED  = 'https://closed.example.com';
my $SELF_RS = 'https://self.example.com';

sub client {
    my ( $id, %extra ) = @_;
    return {
        oidcRPMetaDataOptionsDisplayName                 => $id,
        oidcRPMetaDataOptionsClientID                    => $id,
        oidcRPMetaDataOptionsClientSecret                => $id,
        oidcRPMetaDataOptionsAccessTokenJWT              => 1,
        oidcRPMetaDataOptionsBypassConsent               => 1,
        oidcRPMetaDataOptionsRedirectUris                => "http://$id.com/",
        oidcRPMetaDataOptionsIDTokenSignAlg              => 'HS512',
        oidcRPMetaDataOptionsAllowOffline                => 1,
        oidcRPMetaDataOptionsRefreshToken                => 1,
        oidcRPMetaDataOptionsAllowClientCredentialsGrant => 1,
        %extra,
    };
}

sub rs {
    my ( $id, $identifier, %extra ) = @_;
    return client(
        $id,
        oidcRPMetaDataOptionsEnableRI     => 1,
        oidcRPMetaDataOptionsRIIdentifier => $identifier,
        %extra,
    );
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
                map { $_ => { name => 'cn' } }
                  qw(listed unlisted api m2m closed selfrs)
            },
            oidcRPMetaDataOptions => {
                listed   => client('listed'),
                unlisted => client('unlisted'),

                # Users other than dwho; any client listed here
                api => rs(
                    'api', $API,
                    oidcRPMetaDataOptionsRIAuthorizedRP => 'listed, other',
                    oidcRPMetaDataOptionsRule           => '$uid ne "dwho"',
                ),

                # Machine-to-machine only
                m2m => rs(
                    'm2m', $M2M,
                    oidcRPMetaDataOptionsRIAuthorizedRP => 'listed',
                    oidcRPMetaDataOptionsRule           =>
                      '$_oidc_grant_type eq "clientcredentials"',
                ),

                # Nobody listed
                closed => rs( 'closed', $CLOSED ),

                # A resource server that is also the requesting client
                selfrs => rs( 'selfrs', $SELF_RS ),
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);

my %sid = map { $_ => login( $op, $_ ) } qw(french dwho);

sub auds {
    my ($aud) = @_;
    return !defined $aud ? () : ref $aud eq 'ARRAY' ? @$aud : ($aud);
}

sub has_aud {
    my ( $token, $expected ) = @_;
    my @aud = auds( id_token_payload($token)->{aud} );
    return scalar grep { $_ eq $expected } @aud;
}

sub resources {
    return map { 'resource=' . URI::Escape::uri_escape($_) } @_;
}

# authorize + code grant, returns the token response
sub grant {
    my ( $user, $client, $scope, @resources ) = @_;
    my $query = join '&',
      buildForm( {
            response_type => 'code',
            scope         => $scope,
            client_id     => $client,
            state         => 's',
            redirect_uri  => "http://$client.com/",
        }
      ),
      resources(@resources);
    my $res = $op->_get(
        '/oauth2/authorize',
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$sid{$user}",
    );
    my ($code) = expectRedirection( $res, qr#http://.*code=([^\&]*)# );
    return expectJSON( codeGrant( $op, $client, $code, "http://$client.com/" ) );
}

sub token_request {
    my ( $client, $params, @resources ) = @_;
    my $query = join '&', buildForm($params), resources(@resources);
    return $op->_post(
        '/oauth2/token',
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
        custom => {
                HTTP_AUTHORIZATION => 'Basic '
              . encode_base64( "$client:$client", '' )
        },
    );
}

sub client_credentials {
    my ( $client, @resources ) = @_;
    return expectJSON(
        token_request(
            $client,
            { grant_type => 'client_credentials', scope => 'read' },
            @resources
        )
    );
}

sub refresh {
    my ( $client, $refresh_token ) = @_;
    return expectJSON(
        token_request(
            $client,
            {
                grant_type    => 'refresh_token',
                refresh_token => $refresh_token
            }
        )
    );
}

subtest 'listed client gets the RS audience' => sub {
    my $t = grant( 'french', 'listed', 'openid', $API );
    ok( has_aud( $t->{access_token}, $API ), 'RS in aud' );
    my $intro =
      expectJSON( introspect( $op, 'listed', $t->{access_token} ) );
    ok( ( grep { $_ eq $API } auds( $intro->{aud} ) ),
        'RS in introspection aud' );
};

subtest 'unlisted client does not get the RS audience' => sub {
    my $t = grant( 'french', 'unlisted', 'openid', $API );
    ok( $t->{access_token}, 'token still issued' );
    ok( !has_aud( $t->{access_token}, $API ), 'RS not in aud' );
    my $intro =
      expectJSON( introspect( $op, 'unlisted', $t->{access_token} ) );
    ok( !( grep { $_ eq $API } auds( $intro->{aud} ) ),
        'RS not in introspection aud' );
};

subtest 'an RS that lists no client accepts none' => sub {
    my $t = grant( 'french', 'listed', 'openid', $CLOSED );
    ok( !has_aud( $t->{access_token}, $CLOSED ), 'RS not in aud' );
};

subtest 'a client may target itself' => sub {
    my $t = grant( 'french', 'selfrs', 'openid', $SELF_RS );
    ok( has_aud( $t->{access_token}, $SELF_RS ), 'own RS in aud' );
};

subtest 'user denied by the RS access rule does not get the audience' => sub {
    my $t = grant( 'dwho', 'listed', 'openid', $API );
    ok( $t->{access_token}, 'token still issued' );
    ok( !has_aud( $t->{access_token}, $API ), 'RS not in aud' );
};

subtest 'only the authorized resources are kept' => sub {
    my $t = grant( 'french', 'listed', 'openid', $API, $CLOSED, $M2M );
    ok( has_aud( $t->{access_token}, $API ), 'authorized RS in aud' );
    ok( !has_aud( $t->{access_token}, $CLOSED ), 'unlisted RS not in aud' );
    ok( !has_aud( $t->{access_token}, $M2M ), 'rule-denied RS not in aud' );
};

subtest 'client_credentials: listed client gets the RS audience' => sub {
    my $t = client_credentials( 'listed', $API, $M2M );
    ok( has_aud( $t->{access_token}, $API ), 'RS in aud' );
    ok( has_aud( $t->{access_token}, $M2M ),
        'RS rule sees the clientcredentials grant type' );
};

subtest 'client_credentials: unlisted client does not get the audience' =>
  sub {
    my $t = client_credentials( 'unlisted', $API );
    ok( $t->{access_token}, 'token still issued' );
    ok( !has_aud( $t->{access_token}, $API ), 'RS not in aud' );
  };

subtest 'refresh keeps an authorized audience' => sub {
    my $t = grant( 'french', 'listed', 'openid offline_access', $API );
    ok( $t->{refresh_token}, 'refresh token issued' );
    my $r = refresh( 'listed', $t->{refresh_token} );
    ok( has_aud( $r->{access_token}, $API ), 'RS still in aud' );
};

subtest 'refresh drops an audience the RS no longer authorizes' => sub {
    my $t = grant( 'french', 'listed', 'openid offline_access', $API );
    ok( has_aud( $t->{access_token}, $API ), 'RS in aud at first' );

    # The operator removes the client from the RS list afterwards
    my $opts =
      $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::OIDCResourceIndicators'}
      ->oidc->rpOptions->{api};
    local $opts->{oidcRPMetaDataOptionsRIAuthorizedRP} = 'other';

    my $r = refresh( 'listed', $t->{refresh_token} );
    ok( $r->{access_token}, 'refresh still works' );
    ok( !has_aud( $r->{access_token}, $API ), 'RS no longer in aud' );
};

clean_sessions();
done_testing();
