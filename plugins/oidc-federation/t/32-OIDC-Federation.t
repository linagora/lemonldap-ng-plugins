use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use Crypt::JWT qw(encode_jwt decode_jwt);
use Crypt::PK::RSA;
use MIME::Base64;
use LWP::UserAgent;
use LWP::Protocol::PSGI;
use Plack::Request;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

# --------------------------------------------------------------------------
# Generate keys for the federated RP and Trust Anchor
# --------------------------------------------------------------------------

# Trust Anchor uses the alt keys from oidc-lib
my $ta_private_key = alt_oidc_key_op_private_sig();
my $ta_public_cert = alt_oidc_cert_op_public_sig();

# Build Trust Anchor JWK from cert
my $ta_pk = Crypt::PK::RSA->new();
$ta_pk->import_key( \$ta_public_cert );
my $ta_jwk = $ta_pk->export_key_jwk( 'public', 1 );
$ta_jwk->{kid} = 'ta-key-1';
$ta_jwk->{use} = 'sig';

# Federated RP: generate a fresh RSA key pair
my $rp_pk = Crypt::PK::RSA->new();
$rp_pk->generate_key(256);    # 256 bytes = 2048 bits
my $rp_private_pem = $rp_pk->export_key_pem('private');
my $rp_jwk         = $rp_pk->export_key_jwk( 'public', 1 );
$rp_jwk->{kid} = 'rp-fed-key-1';
$rp_jwk->{use} = 'sig';

# --------------------------------------------------------------------------
# Build the federation simulation:
#   Trust Anchor: https://ta.example.com
#   Federated RP: https://rp-fed.example.com
#
# The RP's Entity Configuration declares authority_hints => [TA]
# The TA's Entity Configuration has a federation_fetch_endpoint
# The TA's fetch endpoint returns a Subordinate Statement about the RP
# --------------------------------------------------------------------------

my $ta_entity_id = 'https://ta.example.com';
my $rp_entity_id = 'https://rp-fed.example.com';

# RP Entity Configuration (self-signed by RP)
my $rp_entity_config_payload = {
    iss              => $rp_entity_id,
    sub              => $rp_entity_id,
    iat              => time(),
    exp              => time() + 86400,
    jwks             => { keys => [$rp_jwk] },
    authority_hints  => [$ta_entity_id],
    metadata         => {
        openid_relying_party => {
            client_id     => $rp_entity_id,
            client_name   => 'Federated RP',
            redirect_uris => ['http://rp-fed.example.com/callback'],
            response_types => ['code'],
            grant_types    => ['authorization_code'],
            token_endpoint_auth_method => 'none',
            id_token_signed_response_alg => 'RS256',
        },
    },
};

my $rp_entity_config_jwt = encode_jwt(
    payload       => to_json($rp_entity_config_payload),
    alg           => 'RS256',
    key           => $rp_pk,
    extra_headers => { typ => 'entity-statement+jwt', kid => 'rp-fed-key-1' },
);

# TA Entity Configuration (self-signed by TA)
my $ta_entity_config_payload = {
    iss  => $ta_entity_id,
    sub  => $ta_entity_id,
    iat  => time(),
    exp  => time() + 86400,
    jwks => { keys => [$ta_jwk] },
    metadata => {
        federation_entity => {
            federation_fetch_endpoint =>
              'https://ta.example.com/federation_fetch',
            federation_list_endpoint =>
              'https://ta.example.com/federation_list',
        },
    },
};

my $ta_entity_config_jwt = encode_jwt(
    payload       => to_json($ta_entity_config_payload),
    alg           => 'RS256',
    key           => \$ta_private_key,
    extra_headers => { typ => 'entity-statement+jwt', kid => 'ta-key-1' },
);

# Subordinate Statement from TA about RP (signed by TA)
my $ta_sub_statement_payload = {
    iss      => $ta_entity_id,
    sub      => $rp_entity_id,
    iat      => time(),
    exp      => time() + 86400,
    jwks     => { keys => [$rp_jwk] },
    metadata => {
        openid_relying_party => {
            client_id     => $rp_entity_id,
            client_name   => 'Federated RP',
            redirect_uris => ['http://rp-fed.example.com/callback'],
            response_types => ['code'],
            grant_types    => ['authorization_code'],
            token_endpoint_auth_method => 'none',
        },
    },
};

my $ta_sub_statement_jwt = encode_jwt(
    payload       => to_json($ta_sub_statement_payload),
    alg           => 'RS256',
    key           => \$ta_private_key,
    extra_headers => { typ => 'entity-statement+jwt', kid => 'ta-key-1' },
);

# --------------------------------------------------------------------------
# Initialize OP with federation config
# --------------------------------------------------------------------------

# Build TA trust anchor config: entity_id => JWKS JSON
my $ta_jwks_json = to_json( { keys => [$ta_jwk] } );

my $op = LLNG::Manager::Test->new( {
        ini => {
            domain                          => 'idp.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            customPlugins                   => '::Plugins::OpenIDFederation',
            issuerDBOpenIDConnectActivation => 1,
            issuerDBOpenIDConnectRule       => '$uid eq "french"',
            oidcRPMetaDataExportedVars      => {
                rp => {
                    email       => "mail",
                    family_name => "cn",
                    name        => "cn"
                },
            },
            oidcRPMetaDataOptions => {
                rp => {
                    oidcRPMetaDataOptionsDisplayName       => "RP",
                    oidcRPMetaDataOptionsIDTokenExpiration  => 3600,
                    oidcRPMetaDataOptionsClientID           => "rpid",
                    oidcRPMetaDataOptionsIDTokenSignAlg     => "RS256",
                    oidcRPMetaDataOptionsClientSecret       => "rpsecret",
                    oidcRPMetaDataOptionsUserIDAttr         => "",
                    oidcRPMetaDataOptionsBypassConsent      => 1,
                    oidcRPMetaDataOptionsRedirectUris => 'http://rp.com/',
                    oidcRPMetaDataOptionsFederationEntityId =>
                      'https://rp.example.com',
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,

            # OpenID Federation config
            oidcFederationEnabled   => 1,
            oidcFederationEntityId  => 'https://op.example.com',
            oidcFederationAllowPrivateHosts => 1,
            oidcFederationCacheTTL          => 0,
            oidcFederationAuthorityHints => 'https://ta.example.com',
            oidcFederationSigningAlg     => 'RS256',
            oidcFederationTrustAnchors   => {
                $ta_entity_id => { jwks => $ta_jwks_json },
            },
        }
    }
);

my $last_fetch_sub;

# Register LWP interceptor AFTER OP creation to override the default handler
LWP::Protocol::PSGI->register(
    sub {
        my $env = $_[0];
        my $uri = ( $env->{REQUEST_URI} || $env->{PATH_INFO} || '' );
        # Reconstruct full URL for matching
        my $scheme = $env->{'psgi.url_scheme'} || 'http';
        my $host   = $env->{HTTP_HOST} || $env->{SERVER_NAME} || '';
        my $full_uri = "${scheme}://${host}${uri}";

        # RP Entity Configuration
        if ( $full_uri =~
            m{^https://rp-fed\.example\.com/\.well-known/openid-federation} )
        {
            return [
                200,
                [ 'Content-Type' => 'application/entity-statement+jwt' ],
                [$rp_entity_config_jwt]
            ];
        }

        # TA Entity Configuration
        elsif ( $full_uri =~
            m{^https://ta\.example\.com/\.well-known/openid-federation} )
        {
            return [
                200,
                [ 'Content-Type' => 'application/entity-statement+jwt' ],
                [$ta_entity_config_jwt]
            ];
        }

        # TA Fetch endpoint
        elsif ( $full_uri =~
            m{^https://ta\.example\.com/federation_fetch\?sub=} )
        {
            $last_fetch_sub = Plack::Request->new($env)->param('sub');
            return [
                200,
                [ 'Content-Type' => 'application/entity-statement+jwt' ],
                [$ta_sub_statement_jwt]
            ];
        }

        # Forward all other requests to the OP
        my $req  = Plack::Request->new($env);
        my $path = $env->{PATH_INFO} || '/';
        if ( $env->{QUERY_STRING} ) {
            $path .= '?' . $env->{QUERY_STRING};
        }
        if ( $req->method =~ /^post$/i ) {
            my $s = $req->content;
            return $op->_post(
                $path, IO::String->new($s),
                length => length($s),
                type   => $req->header('Content-Type'),
            );
        }
        else {
            return $op->_get($path);
        }
    }
);

my $res;

# ==========================================================================
# PART 1: Entity Configuration endpoint
# ==========================================================================
note "Testing /.well-known/openid-federation endpoint";

ok(
    $res = $op->_get(
        '/.well-known/openid-federation',
        accept => 'application/entity-statement+jwt',
    ),
    'Get Entity Configuration'
);
is( $res->[0], 200, 'Entity Configuration returns 200' );

my %headers = @{ $res->[1] };
is( $headers{'Content-Type'}, 'application/entity-statement+jwt',
    'Content-Type is application/entity-statement+jwt' );

my $jwt_string = $res->[2]->[0];
ok( $jwt_string, 'Got JWT response body' );

my $payload = decode_jwt( token => $jwt_string, ignore_signature => 1 );
$payload = from_json($payload) unless ref($payload);

is( $payload->{iss}, 'https://op.example.com', 'iss is correct' );
is( $payload->{sub}, 'https://op.example.com', 'sub equals iss' );
ok( $payload->{iat}, 'iat is present' );
ok( $payload->{exp} > $payload->{iat}, 'exp > iat' );

# JWKS
my $jwk = $payload->{jwks}->{keys}->[0];
is( $jwk->{kty}, 'RSA', 'JWK key type is RSA' );
is( $jwk->{use}, 'sig', 'JWK use is sig' );

# authority_hints
is_deeply( $payload->{authority_hints}, ['https://ta.example.com'],
    'authority_hints is correct' );

# metadata
ok( $payload->{metadata}->{openid_provider}->{issuer},
    'openid_provider.issuer is present' );
ok( $payload->{metadata}->{federation_entity}->{federation_fetch_endpoint},
    'federation_fetch_endpoint is present' );

# Self-signature verification
my $op_pk = Crypt::PK::RSA->new();
$op_pk->import_key($jwk);
my $verified = eval { decode_jwt( token => $jwt_string, key => $op_pk ) };
ok( !$@, 'Entity Configuration self-signature is valid' )
  or diag("Sig verify failed: $@");

# ==========================================================================
# PART 2: OIDC Discovery includes federation fields
# ==========================================================================
note "Testing OIDC discovery with federation fields";

ok( $res = $op->_get( '/.well-known/openid-configuration',
        accept => 'application/json' ),
    'Get OIDC metadata' );
my $json = expectJSON($res);
ok( grep( { $_ eq 'automatic' }
        @{ $json->{client_registration_types_supported} } ),
    'automatic registration type is supported' );

# ==========================================================================
# PART 3: Federation list endpoint
# ==========================================================================
note "Testing federation list endpoint";

ok( $res = $op->_get( '/oauth2/federation_list',
        accept => 'application/json' ),
    'Get federation list' );
$json = expectJSON($res);
ok( grep( { $_ eq 'https://rp.example.com' } @$json ),
    'Federation list contains our RP entity ID' );

# ==========================================================================
# PART 4: Federation fetch endpoint
# ==========================================================================
note "Testing federation fetch endpoint";

ok( $res = $op->_get( '/oauth2/federation_fetch',
        query  => 'sub=https://rp.example.com',
        accept => 'application/entity-statement+jwt' ),
    'Fetch Subordinate Statement for known RP' );
is( $res->[0], 200, 'Fetch returns 200' );

$payload = decode_jwt( token => $res->[2]->[0], ignore_signature => 1 );
$payload = from_json($payload) unless ref($payload);
is( $payload->{iss}, 'https://op.example.com',  'Sub Statement iss correct' );
is( $payload->{sub}, 'https://rp.example.com',  'Sub Statement sub correct' );
is( $payload->{metadata}->{openid_relying_party}->{client_id},
    'rpid', 'RP client_id correct' );

# Error cases
ok( $res = $op->_get( '/oauth2/federation_fetch',
        query => 'sub=https://unknown.example.com' ),
    'Fetch unknown entity' );
is( $res->[0], 404, 'Unknown entity returns 404' );

ok( $res = $op->_get('/oauth2/federation_fetch'), 'Fetch without sub' );
is( $res->[0], 400, 'Missing sub returns 400' );

# ==========================================================================
# PART 5: End-to-end federation RP enrollment via trust chain
# ==========================================================================
note "Testing end-to-end federation RP enrollment";

# Authenticate user
my $query = "user=french&password=french";
ok(
    $res = $op->_post(
        "/",
        IO::String->new($query),
        accept => 'text/html',
        length => length($query),
    ),
    "Post authentication"
);
my $idpId = expectCookie($res);

# The federated RP (https://rp-fed.example.com) attempts OIDC authorization
# The OP doesn't know this client_id statically, so getOidcRpConfig hook
# should resolve it via federation trust chain
$query = buildForm( {
    response_type => 'code',
    scope         => 'openid',
    client_id     => $rp_entity_id,
    state         => 'xyzstate',
    redirect_uri  => 'http://rp-fed.example.com/callback',
} );

ok(
    $res = $op->_get(
        "/oauth2/authorize",
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$idpId",
    ),
    "Authorization request from federated RP"
);

# Expect consent form (PE_CONFIRM)
my ( $host, $tmp );
( $host, $tmp, $query ) = expectForm( $res, '#', undef, 'confirm' );
ok( $query, "Got consent form" );

ok(
    $res = $op->_post(
        "/oauth2/authorize",
        IO::String->new($query),
        accept => 'text/html',
        cookie => "lemonldap=$idpId",
        length => length($query),
    ),
    "Post consent confirmation"
);

# Now expect redirect with authorization code
my ($redirect_url) =
  expectRedirection( $res, qr#(http://rp-fed\.example\.com/callback\?.*)# );
ok( $redirect_url, "Got redirect to federated RP callback" );
like( $redirect_url, qr/\bcode=/, "Redirect contains authorization code" );
like( $redirect_url, qr/\bstate=xyzstate\b/, "Redirect contains state" );

note "Federation RP enrollment succeeded - trust chain resolved, code issued";

my $plugin =
  $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::OpenIDFederation'};

subtest 'a statement of the wrong JSON type gives no RP and no die' => sub {
    my $saved_ta  = $ta_entity_config_jwt;
    my $saved_sub = $ta_sub_statement_jwt;
    my $saved_rp  = $rp_entity_config_jwt;

    for my $payload (
        '[1,2]',
        to_json( { %$ta_entity_config_payload, metadata => 'abc' } ),
      )
    {
        $ta_entity_config_jwt = encode_jwt(
            payload       => $payload,
            alg           => 'RS256',
            key           => \$ta_private_key,
            extra_headers => { typ => 'entity-statement+jwt', kid => 'ta-key-1' },
        );
        my %config;
        my $ok = eval {
            $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
            1;
        };
        ok( $ok, "no die: $payload" ) or diag $@;
        ok( !$config{confKey}, 'no virtual RP' );
    }

    $ta_entity_config_jwt = $saved_ta;

    for my $jwks ( 'abc', [1] ) {
        $rp_entity_config_jwt = encode_jwt(
            payload => to_json( { %$rp_entity_config_payload, jwks => $jwks } ),
            alg           => 'RS256',
            key           => $rp_pk,
            extra_headers => { typ => 'entity-statement+jwt', kid => 'rp-fed-key-1' },
        );
        my %config;
        my $ok = eval {
            $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
            1;
        };
        ok( $ok, 'no die' ) or diag $@;
        ok( !$config{confKey}, 'no virtual RP for a malformed leaf jwks' );
    }

    $rp_entity_config_jwt = $saved_rp;

    $ta_sub_statement_jwt = encode_jwt(
        payload => to_json(
            { %$ta_sub_statement_payload, metadata_policy => 'abc' }
        ),
        alg           => 'RS256',
        key           => \$ta_private_key,
        extra_headers => { typ => 'entity-statement+jwt', kid => 'ta-key-1' },
    );
    my %config;
    my $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die for a scalar metadata_policy' ) or diag $@;
    ok( !$config{confKey}, 'no virtual RP for a scalar metadata_policy' );

    $ta_sub_statement_jwt = $saved_sub;
};

subtest 'a policy operand that is not a list refuses the entity' => sub {
    my $saved = $ta_sub_statement_jwt;

    for my $operator (qw(one_of subset_of superset_of add)) {
        $ta_sub_statement_jwt = encode_jwt(
            payload => to_json( {
                    %$ta_sub_statement_payload,
                    metadata_policy => {
                        openid_relying_party => {
                            response_types => { $operator => 'scalar' },
                        },
                    },
            } ),
            alg           => 'RS256',
            key           => \$ta_private_key,
            extra_headers => { typ => 'entity-statement+jwt', kid => 'ta-key-1' },
        );
        my %config;
        my $ok = eval {
            $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
            1;
        };
        ok( $ok, "$operator: no die" ) or diag $@;
        ok( !$config{confKey}, "$operator: no virtual RP" );
    }

    $ta_sub_statement_jwt = $saved;
};

subtest 'a valid metadata policy is applied' => sub {
    my $saved = $ta_sub_statement_jwt;
    $ta_sub_statement_jwt = encode_jwt(
        payload => to_json( {
                %$ta_sub_statement_payload,
                metadata_policy => {
                    openid_relying_party => {
                        client_name    => { value => 'Policy Name' },
                        response_types => { subset_of => ['code'] },
                    },
                },
        } ),
        alg           => 'RS256',
        key           => \$ta_private_key,
        extra_headers => { typ => 'entity-statement+jwt', kid => 'ta-key-1' },
    );

    my %config;
    my $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die' ) or diag $@;
    ok( $config{confKey}, 'virtual RP built' );
    is( $config{options}->{oidcRPMetaDataOptionsDisplayName},
        'Policy Name', 'value operator applied' );
    is( $config{options}->{oidcRPMetaDataOptionsAllowedResponseTypes},
        'code', 'subset_of operator applied' );

    $ta_sub_statement_jwt = $saved;
};

subtest 'an essential policy claim that is missing refuses the entity' => sub {
    my $saved = $ta_sub_statement_jwt;
    $ta_sub_statement_jwt = encode_jwt(
        payload => to_json( {
                %$ta_sub_statement_payload,
                metadata_policy => {
                    openid_relying_party => {
                        missing_claim => { essential => 1 },
                    },
                },
        } ),
        alg           => 'RS256',
        key           => \$ta_private_key,
        extra_headers => { typ => 'entity-statement+jwt', kid => 'ta-key-1' },
    );

    my %config;
    my $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die' ) or diag $@;
    ok( !$config{confKey}, 'no virtual RP' );

    $ta_sub_statement_jwt = $saved;
};

subtest 'RP metadata of the wrong JSON type gives no RP and no die' => sub {
    my $saved = $rp_entity_config_jwt;
    my $meta  = $rp_entity_config_payload->{metadata}{openid_relying_party};

    for my $rp_meta (
        { %$meta, redirect_uris  => 'http://x/' },
        { %$meta, response_types => 'code' },
        { %$meta, grant_types    => 'authorization_code' },
        'not an object',
      )
    {
        $rp_entity_config_jwt = encode_jwt(
            payload => to_json( {
                    %$rp_entity_config_payload,
                    metadata => { openid_relying_party => $rp_meta },
            } ),
            alg           => 'RS256',
            key           => $rp_pk,
            extra_headers => { typ => 'entity-statement+jwt', kid => 'rp-fed-key-1' },
        );
        my %config;
        my $ok = eval {
            $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
            1;
        };
        ok( $ok, 'no die' ) or diag $@;
        ok( !$config{confKey}, 'no virtual RP' );
    }

    $rp_entity_config_jwt = $saved;
};

subtest 'policy violations refuse the entity' => sub {
    my $saved = $ta_sub_statement_jwt;

    for my $policy (
        { client_name => { one_of => ['Other'] } },
        { response_types => { superset_of => ['code', 'token'] } },
        { token_endpoint_auth_method => { one_of => ['private_key_jwt'] } },
      )
    {
        $ta_sub_statement_jwt = encode_jwt(
            payload => to_json( {
                    %$ta_sub_statement_payload,
                    metadata_policy => { openid_relying_party => $policy },
            } ),
            alg           => 'RS256',
            key           => \$ta_private_key,
            extra_headers => { typ => 'entity-statement+jwt', kid => 'ta-key-1' },
        );
        my %config;
        my $ok = eval {
            $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
            1;
        };
        ok( $ok, 'no die' ) or diag $@;
        ok( !$config{confKey}, 'no virtual RP' );
    }

    # A satisfied superset_of is still accepted.
    $ta_sub_statement_jwt = encode_jwt(
        payload => to_json( {
                %$ta_sub_statement_payload,
                metadata_policy => {
                    openid_relying_party => {
                        response_types => { superset_of => ['code'] },
                    },
                },
        } ),
        alg           => 'RS256',
        key           => \$ta_private_key,
        extra_headers => { typ => 'entity-statement+jwt', kid => 'ta-key-1' },
    );
    my %config;
    my $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die for a satisfied superset_of' ) or diag $@;
    ok( $config{confKey}, 'a satisfied superset_of builds the RP' );

    $ta_sub_statement_jwt = $saved;
};

subtest 'federation registration hook contract' => sub {
    my $req = bless { data => {} }, 't::FedRequest';
    my $rc = $plugin->federationRegistrationCheck(
        $req,
        {
            trust_chain => 'ignored',
            client_id   => $rp_entity_id,
        }
    );
    is( $rc, 0, 'a valid trust chain allows registration' );
    is( $req->data->{federationEntityId}, $rp_entity_id,
        'the entity id is stored for the response hook' );

    my $saved = $rp_entity_config_jwt;
    $rp_entity_config_jwt = 'not-a-jwt';
    my $bad = bless { data => {} }, 't::FedRequest';
    my $bad_rc = $plugin->federationRegistrationCheck(
        $bad,
        {
            trust_chain => 'ignored',
            client_id   => $rp_entity_id,
        }
    );
    isnt( $bad_rc, 0, 'an invalid trust chain is refused' );
    ok( !$bad->data->{federationEntityId}, 'nothing stored for an invalid chain' );

    $rp_entity_config_jwt = $saved;
};

{
    package t::FedRequest;
    sub data { return $_[0]->{data} ||= {} }
}

subtest 'trust chain statements are linked and time-bounded' => sub {
    my $saved_sub = $ta_sub_statement_jwt;

    for my $mutation (
        { iss => 'https://other.example.com' },
        { sub => 'https://other.example.com' },
        { exp => time - 10 },
      )
    {
        $ta_sub_statement_jwt = encode_jwt(
            payload => to_json(
                { %$ta_sub_statement_payload, %$mutation }
            ),
            alg           => 'RS256',
            key           => \$ta_private_key,
            extra_headers => { typ => 'entity-statement+jwt', kid => 'ta-key-1' },
        );
        my %config;
        my $ok = eval {
            $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
            1;
        };
        ok( $ok, 'no die' ) or diag $@;
        ok( !$config{confKey}, 'no virtual RP for ' . to_json($mutation) );
    }

    $ta_sub_statement_jwt = $saved_sub;

    # The leaf is not signed by the keys the superior vouched for.
    $ta_sub_statement_jwt = encode_jwt(
        payload => to_json( {
                %$ta_sub_statement_payload,
                jwks => { keys => [$ta_jwk] },
        } ),
        alg           => 'RS256',
        key           => \$ta_private_key,
        extra_headers => { typ => 'entity-statement+jwt', kid => 'ta-key-1' },
    );
    my %config;
    my $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die for an unvouched leaf' ) or diag $@;
    ok( !$config{confKey}, 'no virtual RP for an unvouched leaf' );
    $ta_sub_statement_jwt = $saved_sub;

    # A leaf without embedded jwks cannot be verified at all.
    my $saved_rp = $rp_entity_config_jwt;
    my %leaf     = %$rp_entity_config_payload;
    delete $leaf{jwks};
    $rp_entity_config_jwt = encode_jwt(
        payload       => to_json(\%leaf),
        alg           => 'RS256',
        key           => $rp_pk,
        extra_headers => { typ => 'entity-statement+jwt', kid => 'rp-fed-key-1' },
    );
    %config = ();
    $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die for a leaf without jwks' ) or diag $@;
    ok( !$config{confKey}, 'no virtual RP for a leaf without jwks' );
    $rp_entity_config_jwt = $saved_rp;
};

subtest 'configured trust anchor keys are enforced' => sub {
    my $saved_anchors = $plugin->trustAnchors;

    $plugin->trustAnchors(
        { $ta_entity_id => { jwks => { keys => [$rp_jwk] } } } );
    my %config;
    my $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die with a wrong anchor key' ) or diag $@;
    ok( !$config{confKey}, 'no virtual RP with a wrong anchor key' );

    $plugin->trustAnchors( { $ta_entity_id => { jwks => undef } } );
    %config = ();
    $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die without anchor keys' ) or diag $@;
    ok( !$config{confKey}, 'no virtual RP without anchor keys' );

    $plugin->trustAnchors($saved_anchors);
};

subtest 'entity identifiers must be https URLs without query or fragment' => sub {
    for my $entity_id (
        'http://rp-fed.example.com',
        'https://rp-fed.example.com/?x=1',
        'https://rp-fed.example.com/#frag',
      )
    {
        my %config;
        my $ok = eval {
            $plugin->resolveRPFromFederation( undef, $entity_id, \%config );
            1;
        };
        ok( $ok, 'no die' ) or diag $@;
        ok( !$config{confKey}, "no virtual RP for $entity_id" );
    }

    my $saved_rp = $rp_entity_config_jwt;
    $rp_entity_config_jwt = encode_jwt(
        payload => to_json( {
                %$rp_entity_config_payload,
                authority_hints => ['http://ta.example.com'],
        } ),
        alg           => 'RS256',
        key           => $rp_pk,
        extra_headers => { typ => 'entity-statement+jwt', kid => 'rp-fed-key-1' },
    );
    my %config;
    my $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die for an http authority hint' ) or diag $@;
    ok( !$config{confKey}, 'no virtual RP for an http authority hint' );
    $rp_entity_config_jwt = $saved_rp;

    my $saved_ta = $ta_entity_config_jwt;
    my %ta       = %$ta_entity_config_payload;
    my %metadata = %{ $ta_entity_config_payload->{metadata} };
    $metadata{federation_entity} = {
        %{ $ta_entity_config_payload->{metadata}->{federation_entity} },
        federation_fetch_endpoint => 'http://ta.example.com/federation_fetch',
    };
    $ta{metadata} = \%metadata;
    $ta_entity_config_jwt = encode_jwt(
        payload       => to_json(\%ta),
        alg           => 'RS256',
        key           => \$ta_private_key,
        extra_headers => { typ => 'entity-statement+jwt', kid => 'ta-key-1' },
    );
    %config = ();
    $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die for an http fetch endpoint' ) or diag $@;
    ok( !$config{confKey}, 'no virtual RP for an http fetch endpoint' );
    $ta_entity_config_jwt = $saved_ta;
};

subtest 'the subject is encoded in the fetch query' => sub {
    $last_fetch_sub = undef;
    my $jwt = $plugin->fetchSubordinateStatement(
        'https://ta.example.com/federation_fetch',
        'https://rp-fed.example.com/a&b',
        [$ta_jwk],
    );
    ok( $jwt, 'statement fetched' );
    is( $last_fetch_sub, 'https://rp-fed.example.com/a&b',
        'the subject arrives decoded exactly once' );
};

subtest 'trust chain resolutions are cached' => sub {
    my $conf      = $plugin->conf;
    my $saved_ttl = $conf->{oidcFederationCacheTTL};
    my $saved_sub = $ta_sub_statement_jwt;
    $conf->{oidcFederationCacheTTL} = 60;
    $plugin->_chainCache({});

    my %config;
    my $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die' ) or diag $@;
    ok( $config{confKey}, 'the first resolution builds the RP' );

    $ta_sub_statement_jwt = encode_jwt(
        payload => to_json( {
                %$ta_sub_statement_payload,
                sub => 'https://other.example.com',
        } ),
        alg           => 'RS256',
        key           => \$ta_private_key,
        extra_headers => { typ => 'entity-statement+jwt', kid => 'ta-key-1' },
    );
    %config = ();
    $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die with the cached chain' ) or diag $@;
    ok( $config{confKey}, 'the cached chain is reused' );

    $plugin->_chainCache({});
    %config = ();
    $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die without the cache' ) or diag $@;
    ok( !$config{confKey}, 'without the cache the invalid statement is refused' );

    $ta_sub_statement_jwt          = $saved_sub;
    $conf->{oidcFederationCacheTTL} = $saved_ttl;
    $plugin->_chainCache({});
};

subtest 'federation fetch guards' => sub {
    my @hints = map { "https://h$_.example.com" } 1 .. 10;
    is( scalar( $plugin->_candidateHints( \@hints ) ), 5,
        'authority hints are capped' );

    my $budget = { left => 3 };
    ok( $plugin->_consumeBudget( $budget, 2 ), 'budget available' );
    ok( !$plugin->_consumeBudget( $budget, 2 ), 'budget exhausted' );
};

{
    package t::FedLogger;
    sub new     { bless {}, shift }
    sub debug   { }
    sub info    { }
    sub notice  { }
    sub warn    { }
    sub error   { }

    package t::FedRole;
    use Mouse;
    has conf   => ( is => 'rw', default => sub { {} } );
    has logger => ( is => 'rw', default => sub { t::FedLogger->new } );
    has p      => ( is => 'rw', default => sub { {} } );
    with 'Lemonldap::NG::Portal::Lib::OpenIDFederation';
}

subtest 'default federation UA blocks private hosts' => sub {
    SKIP: {
        skip 'LWPx::ParanoidAgent not installed', 3
          unless eval { require LWPx::ParanoidAgent; 1 };

        my $role =
          t::FedRole->new( conf => { oidcFederationFetchTimeout => 1 } );
        my $ua = $role->ua;
        isa_ok( $ua, 'LWPx::ParanoidAgent' );
        for my $url ( 'https://127.0.0.1/', 'https://100.64.0.1/' ) {
            my $res = $ua->get($url);
            is( $res->code, 403, "$url is blocked" );
        }
    }
};

subtest 'a resolution deadline stops the walk' => sub {
    my $conf      = $plugin->conf;
    my $saved     = $conf->{oidcFederationResolutionTimeout};
    $conf->{oidcFederationResolutionTimeout} = 0;
    $plugin->_chainCache({});

    my %config;
    my $ok = eval {
        $plugin->resolveRPFromFederation( undef, $rp_entity_id, \%config );
        1;
    };
    ok( $ok, 'no die' ) or diag $@;
    ok( $config{confKey}, 'a zero timeout falls back to the default' );

    my $budget = { left => 3, deadline => time - 1 };
    ok( !$plugin->_consumeBudget( $budget, 1 ), 'the budget deadline is enforced' );

    $conf->{oidcFederationResolutionTimeout} = $saved;
    $plugin->_chainCache({});
};

clean_sessions();
done_testing();
