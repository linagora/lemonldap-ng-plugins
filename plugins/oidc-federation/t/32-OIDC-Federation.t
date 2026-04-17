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
            oidcFederationAuthorityHints => 'https://ta.example.com',
            oidcFederationSigningAlg     => 'RS256',
            oidcFederationTrustAnchors   => {
                $ta_entity_id => { jwks => $ta_jwks_json },
            },
        }
    }
);

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

clean_sessions();
done_testing();
