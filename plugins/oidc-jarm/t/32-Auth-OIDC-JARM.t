use warnings;
use Test::More;
use strict;
use IO::String;
use LWP::UserAgent;
use LWP::Protocol::PSGI;
use URI::QueryParam;
use Crypt::JWT qw(encode_jwt);
use JSON qw(to_json);
use Lemonldap::NG::Portal::Main::Constants qw(PE_OK PE_ERROR);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my ( $op, $rp, $res );

LWP::Protocol::PSGI->register(
    sub {
        my $req = Plack::Request->new(@_);
        ok( $req->uri =~ m#http://auth.((?:o|r)p).com(.*)#, ' REST request' );
        my $host = $1;
        my $url  = $2;
        my ( $res, $client );
        if ( $host eq 'op' ) {
            pass("  Request from RP to OP,     endpoint $url");
            $client = $op;
        }
        elsif ( $host eq 'rp' ) {
            pass('  Request from OP to RP');
            $client = $rp;
        }
        else {
            fail('  Aborting REST request (external)');
            return [ 500, [], [] ];
        }
        if ( $req->method =~ /^post$/i ) {
            my $s = $req->content;
            ok(
                $res = $client->_post(
                    $url, IO::String->new($s),
                    length => length($s),
                    type   => $req->header('Content-Type'),
                ),
                '  Execute request'
            );
        }
        else {
            ok(
                $res = $client->_get(
                    $url,
                    custom => {
                        HTTP_AUTHORIZATION => $req->header('Authorization'),
                    }
                ),
                '  Execute request'
            );
        }
        ok( $res->[0] == 200, '  Response is 200' );
        ok( getHeader( $res, 'Content-Type' ) =~ m#^application/json#,
            '  Content is JSON' )
          or explain( $res->[1], 'Content-Type => application/json' );
        return $res;
    }
);

# Initialization
ok( $op = register( 'op', sub { op() } ), 'OP portal' );

ok( $res = $op->_get('/oauth2/jwks'), 'Get JWKS,     endpoint /oauth2/jwks' );
expectOK($res);
my $jwks = $res->[2]->[0];

ok(
    $res = $op->_get('/.well-known/openid-configuration'),
    'Get metadata, endpoint /.well-known/openid-configuration'
);
expectOK($res);
my $metadata = $res->[2]->[0];

&Lemonldap::NG::Handler::Main::cfgNum( 0, 0 );
ok( $rp = register( 'rp', sub { rp( $jwks, $metadata ) } ), 'RP portal' );

# Test 1: Verify response_mode is in the authorization request
subtest "RP requests response_mode=query.jwt" => sub {
    plan tests => 4;

    # Query RP for auth
    ok( $res = $rp->_get( '/', accept => 'text/html' ), 'Unauth RP request' );

    my ( $url, $query ) = expectRedirection( $res,
        qr#http://auth.op.com(/oauth2/authorize)\?(.*)$# );

    # Check that response_mode is present in the request
    my $uri = URI->new;
    $uri->query($query);
    is( $uri->query_param('response_mode'),
        'query.jwt', 'response_mode=query.jwt is in request' );
};

# Test 2: Full JARM flow - OP responds with JARM, RP processes it
subtest "Full JARM authentication flow" => sub {

    # Query RP for auth
    ok( $res = $rp->_get( '/', accept => 'text/html' ), 'Unauth RP request' );

    my ( $url, $query ) = expectRedirection( $res,
        qr#http://auth.op.com(/oauth2/authorize)\?(.*)$# );

    # Push request to OP
    ok(
        $res = $op->_get( $url, query => $query, accept => 'text/html' ),
        "Push request to OP,         endpoint $url"
    );
    expectOK($res);

    # Authenticate to OP
    $query = "user=french&password=french&$query";
    ok(
        $res = $op->_post(
            $url,
            IO::String->new($query),
            accept => 'text/html',
            length => length($query),
        ),
        "Post authentication,        endpoint $url"
    );
    my $idpId = expectCookie($res);

    # Skip consent if not required
    my ( $host, $tmp );
    if ( $res->[0] == 200 ) {
        ( $host, $tmp, $query ) = expectForm( $res, '#', undef, 'confirm' );
        ok(
            $res = $op->_post(
                $url,
                IO::String->new($query),
                accept => 'text/html',
                cookie => "lemonldap=$idpId",
                length => length($query),
            ),
            "Confirm consent"
        );
    }
    else {
        pass("No consent needed");
    }

    # Expect redirect to RP with JARM response parameter
    # The redirect URL format: http://auth.rp.com/?openidconnectcallback=1&response=<JWT>
    my ($redirect_url) = expectRedirection( $res,
        qr#(http://auth.rp.com/\?.*)$# );

    # Parse the full redirect URL to check for 'response' parameter
    my $uri = URI->new($redirect_url);
    my $jarm_response = $uri->query_param('response');
    ok( $jarm_response, 'JARM response parameter found' )
      or diag("Redirect URL: $redirect_url");

    # Get the query string for passing to RP
    $query = $uri->query;

    # Push callback to RP - it should decode JARM and complete auth
    ok(
        $res = $rp->_get(
            '/',
            query  => "openidconnectcallback=1&$query",
            accept => 'text/html',
        ),
        "Push callback to RP"
    );

    # Should get the session cookie (authentication completed)
    my $rpId = expectCookie($res);
    ok( $rpId, 'RP session created - JARM client flow successful' );
};

subtest 'a forged response leaves the state usable' => sub {
    my $res = $rp->_get( '/', accept => 'text/html' );
    my ( $url, $query ) = expectRedirection( $res,
        qr#http://auth.op.com(/oauth2/authorize)\?(.*)$# );
    my $state = URI->new("http://x/?$query")->query_param('state');

    my $key    = alt_oidc_key_op_private_sig();
    my $forged = encode_jwt(
        payload => to_json( {
            iss   => 'http://auth.op.com/',
            aud   => 'rpid',
            exp   => time + 300,
            state => $state,
            code  => 'forged',
        } ),
        alg => 'RS256',
        key => \$key,
    );
    $res = $rp->_get(
        '/',
        query  => "openidconnectcallback=1&response=$forged",
        accept => 'text/html',
    );
    ok( !getCookies($res)->{lemonldap}, 'no session from a forged response' );

    my $idpId = login( $op, 'french' );
    $res = $op->_get(
        $url,
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$idpId",
    );
    my $real =
      URI->new( getHeader( $res, 'Location' ) )->query_param('response');
    ok( $real, 'the genuine response is available' );

    $res = $rp->_get(
        '/',
        query  => "openidconnectcallback=1&response=$real",
        accept => 'text/html',
    );
    ok( getCookies($res)->{lemonldap},
        'the genuine response still opens a session' );
};

subtest 'a response whose payload is not an object is refused' => sub {
    for my $jwt (
        'eyJhbGciOiJSUzI1NiJ9.WzEsMl0.c2ln',    # [1,2]
        'eyJhbGciOiJSUzI1NiJ9.ImFiYyI.c2ln',    # "abc"
        'MQ.Mg.Mw.NA.NQ.Ng',                    # 2
      )
    {
        my $res = eval {
            $rp->_get(
                '/',
                query  => "openidconnectcallback=1&response=$jwt",
                accept => 'text/html',
            );
        };
        is( $@, '', "no die for $jwt" );
        ok( $res, 'response returned' );
        ok( !getCookies($res)->{lemonldap}, 'no session' );
    }
};

subtest 'JARM response mode rewriting' => sub {
    my $plugin =
      $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::OIDCJarm'};
    ok( $plugin, 'JARM plugin loaded' );

    # processJarmRequest only needs ->data on the request object.
    {
        package t::JarmReq;
        sub new  { bless { data => {} }, shift }
        sub data { $_[0]{data} }
    }

    my @cases = (
        [ 'query.jwt',      'code',     'query' ],
        [ 'fragment.jwt',   'code',     'fragment' ],
        [ 'form_post.jwt',  'code',     'form_post' ],
        [ 'jwt',            'code',     'query' ],
        [ 'jwt',            'id_token', 'fragment' ],
    );
    for my $case (@cases) {
        my ( $mode, $response_type, $base ) = @$case;
        my $req          = t::JarmReq->new;
        my $oidc_request = {
            client_id     => 'rpid',
            response_mode => $mode,
            response_type => $response_type,
        };
        is( $plugin->processJarmRequest( $req, $oidc_request ),
            PE_OK, "$mode/$response_type: accepted" );
        is( $oidc_request->{response_mode},
            $base, "$mode/$response_type: base mode" );
        is( $req->data->{jarm_response_mode},
            $mode, "$mode/$response_type: original kept" );
    }

    # A signed request object takes precedence over the query string.
    {
        my $request_object = encode_jwt(
            payload => { response_mode => 'query' },
            alg     => 'HS256',
            key     => 'request-object-key',
        );
        my $req          = t::JarmReq->new;
        my $oidc_request = {
            client_id     => 'rpid',
            response_mode => 'query.jwt',
            request       => $request_object,
            response_type => 'code',
        };
        is( $plugin->processJarmRequest( $req, $oidc_request ),
            PE_OK, 'request object query: accepted' );
        ok( !exists $req->data->{jarm_response_mode},
            'request object query: no JARM mode' );
        is( $oidc_request->{response_mode},
            'query', 'request object query: mode copied' );

        # A request object that asks for JARM wins over a plain query string.
        $request_object = encode_jwt(
            payload => { response_mode => 'query.jwt' },
            alg     => 'HS256',
            key     => 'request-object-key',
        );
        $req          = t::JarmReq->new;
        $oidc_request = {
            client_id     => 'rpid',
            response_mode => 'query',
            request       => $request_object,
            response_type => 'code',
        };
        is( $plugin->processJarmRequest( $req, $oidc_request ),
            PE_OK, 'request object JARM: accepted' );
        is( $req->data->{jarm_response_mode},
            'query.jwt', 'request object JARM: mode recorded' );
        is( $oidc_request->{response_mode},
            'query', 'request object JARM: base mode' );
    }

    # A PAR request_uri carries no response_mode yet: leave it to oidc-par,
    # which calls processJarmRequest() back on the resolved request.
    {
        my $par_module =
          'Lemonldap::NG::Portal::Plugins::OIDCPushedAuthRequest';
        my $saved = $plugin->p->loadedModules->{$par_module};
        $plugin->p->loadedModules->{$par_module} = bless {}, 't::FakePAR';

        my $req          = t::JarmReq->new;
        my $oidc_request = {
            client_id     => 'rpid',
            request_uri   => 'urn:ietf:params:oauth:request_uri:abc',
            response_type => 'code',
        };
        is( $plugin->processJarmRequest( $req, $oidc_request ),
            PE_OK, 'PAR request_uri: skipped' );
        ok( !exists $req->data->{jarm_response_mode},
            'PAR request_uri: no JARM mode recorded' );

        if ( defined $saved ) {
            $plugin->p->loadedModules->{$par_module} = $saved;
        }
        else {
            delete $plugin->p->loadedModules->{$par_module};
        }
    }

    # The request object, resolved after our first pass, can override the
    # query string: a non-JARM mode clears the stored JARM mode.
    {
        my $req = t::JarmReq->new;
        $req->data->{jarm_response_mode} = 'query.jwt';
        my $oidc_request = {
            client_id     => 'rpid',
            response_mode => 'query',
            response_type => 'code',
        };
        is( $plugin->processJarmRequest( $req, $oidc_request ),
            PE_OK, 'non-JARM request: accepted' );
        ok( !exists $req->data->{jarm_response_mode},
            'non-JARM request: stored JARM mode cleared' );
    }

    # An RP without oidcRPMetaDataOptionsJarm must be refused early.
    my $req = t::JarmReq->new;
    my $oidc_request = {
        client_id     => 'rpid2',
        response_mode => 'query.jwt',
        response_type => 'code',
    };
    is( $plugin->processJarmRequest( $req, $oidc_request ),
        PE_ERROR, 'JARM disabled: refused with PE_ERROR' );
};

clean_sessions();
done_testing();

sub op {
    return LLNG::Manager::Test->new( {
            ini => {
                domain                          => 'idp.com',
                portal                          => 'http://auth.op.com/',
                authentication                  => 'Demo',
                userDB                          => 'Same',
                issuerDBOpenIDConnectActivation => "1",
                customPlugins  => '::Plugins::OIDCJarm',
                restSessionServer               => 1,
                restExportSecretKeys            => 1,
                oidcRPMetaDataExportedVars      => {
                    rp => {
                        email       => "mail",
                        family_name => "cn",
                        name        => "cn",
                    }
                },
                oidcServiceAllowHybridFlow            => 1,
                oidcServiceAllowImplicitFlow          => 1,
                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcRPMetaDataOptions                 => {
                    rp => {
                        oidcRPMetaDataOptionsDisplayName       => "RP",
                        oidcRPMetaDataOptionsIDTokenExpiration => 3600,
                        oidcRPMetaDataOptionsClientID          => "rpid",
                        oidcRPMetaDataOptionsIDTokenSignAlg    => "RS256",
                        oidcRPMetaDataOptionsBypassConsent     => 1,
                        oidcRPMetaDataOptionsClientSecret      => "rpsecret",
                        oidcRPMetaDataOptionsUserIDAttr        => "",
                        oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                        oidcRPMetaDataOptionsRedirectUris =>
                          'http://auth.rp.com/?openidconnectcallback=1',
                        # Enable JARM on OP side
                        oidcRPMetaDataOptionsJarm        => 'allowed',
                        oidcRPMetaDataOptionsJarmSignAlg => 'RS256',
                    },
                    rp2 => {
                        oidcRPMetaDataOptionsDisplayName  => "RP2",
                        oidcRPMetaDataOptionsClientID     => "rpid2",
                        oidcRPMetaDataOptionsClientSecret => "rpsecret2",
                        oidcRPMetaDataOptionsUserIDAttr   => "",
                        oidcRPMetaDataOptionsRedirectUris =>
                          'http://auth.rp.com/?openidconnectcallback=1',
                    }
                },
                oidcOPMetaDataOptions           => {},
                oidcOPMetaDataJSON              => {},
                oidcOPMetaDataJWKS              => {},
                oidcServiceMetaDataAuthnContext => {
                    'loa-4' => 4,
                    'loa-1' => 1,
                    'loa-5' => 5,
                    'loa-2' => 2,
                    'loa-3' => 3
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            }
        }
    );
}

sub rp {
    my ( $jwks, $metadata ) = @_;
    return LLNG::Manager::Test->new( {
            ini => {
                domain                     => 'rp.com',
                portal                     => 'http://auth.rp.com/',
                authentication             => 'OpenIDConnect',
                userDB                     => 'Same',
                customPlugins              => '::Plugins::OIDCJarmClient',
                restSessionServer          => 1,
                restExportSecretKeys       => 1,
                oidcOPMetaDataExportedVars => {
                    op => {
                        cn   => "name",
                        uid  => "sub",
                        sn   => "family_name",
                        mail => "email",
                    }
                },
                oidcOPMetaDataOptions => {
                    op => {
                        oidcOPMetaDataOptionsCheckJWTSignature => 1,
                        oidcOPMetaDataOptionsJWKSTimeout       => 0,
                        oidcOPMetaDataOptionsClientSecret      => "rpsecret",
                        oidcOPMetaDataOptionsScope => "openid profile email",
                        oidcOPMetaDataOptionsStoreIDToken     => 0,
                        oidcOPMetaDataOptionsMaxAge           => 30,
                        oidcOPMetaDataOptionsDisplay          => "",
                        oidcOPMetaDataOptionsClientID         => "rpid",
                        oidcOPMetaDataOptionsUseNonce         => 1,
                        oidcOPMetaDataOptionsConfigurationURI =>
                          "https://auth.op.com/.well-known/openid-configuration",
                        # Enable JARM on RP side (client)
                        oidcOPMetaDataOptionsResponseMode => "query.jwt",
                    }
                },
                oidcOPMetaDataJWKS => {
                    op => $jwks,
                },
                oidcOPMetaDataJSON => {
                    op => $metadata,
                },
            }
        }
    );
}
