package Lemonldap::NG::Portal::Plugins::OpenIDFederation;

use strict;
use Mouse;
use JSON qw(from_json to_json);
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_DONE
  PE_SENDRESPONSE
);

our $VERSION = '2.21.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

with 'Lemonldap::NG::Portal::Lib::OpenIDFederation';

use constant hook => {
    oidcGenerateMetadata           => 'addFederationMetadata',
    getOidcRpConfig                => 'resolveRPFromFederation',
    oidcGotRegistrationRequest     => 'federationRegistrationCheck',
    oidcGenerateRegistrationResponse => 'federationRegistrationResponse',
};

# Cached trust anchors parsed from config
has trustAnchors => (
    is      => 'rw',
    lazy    => 1,
    builder => '_buildTrustAnchors',
);

sub _buildTrustAnchors {
    my ($self) = @_;
    my $conf_anchors = $self->conf->{oidcFederationTrustAnchors} || {};
    my %anchors;

    # Config format: { entityId => { jwks => '...' } }
    for my $entity_id ( keys %$conf_anchors ) {
        my $anchor = $conf_anchors->{$entity_id};
        my $jwks;
        if ( $anchor->{jwks} && !ref( $anchor->{jwks} ) ) {
            $jwks = eval { from_json( $anchor->{jwks} ) };
            if ($@) {
                $self->logger->error(
                    "Invalid JWKS for trust anchor $entity_id: $@");
                next;
            }
        }
        else {
            $jwks = $anchor->{jwks};
        }
        $anchors{$entity_id} = { jwks => $jwks };
    }

    return \%anchors;
}

sub init {
    my ($self) = @_;
    return 0 unless $self->SUPER::init();

    # Register /.well-known/openid-federation endpoint
    $self->addUnauthRoute(
        '.well-known' => { 'openid-federation' => 'entityConfiguration' },
        ['GET']
    );
    $self->addAuthRoute(
        '.well-known' => { 'openid-federation' => 'entityConfiguration' },
        ['GET']
    );

    # Register federation fetch endpoint
    $self->addUnauthRoute(
        $self->path => { 'federation_fetch' => 'fetchEndpoint' },
        ['GET']
    );

    # Register federation list endpoint
    $self->addUnauthRoute(
        $self->path => { 'federation_list' => 'listEndpoint' },
        ['GET']
    );

    $self->logger->info("OpenID Federation plugin initialized");
    return 1;
}

### ENDPOINTS

# /.well-known/openid-federation - serves our Entity Configuration
sub entityConfiguration {
    my ( $self, $req ) = @_;

    my $entity_id = $self->_getEntityId($req);

    # Get signing key
    my $key_id =
      $self->conf->{oidcFederationSigningKey} || 'default-oidc-sig';
    my $priv_key = $self->oidc->get_private_key($key_id);
    unless ($priv_key) {
        $self->logger->error("No signing key found for federation");
        return $self->p->sendError( $req, 'server_error', 500 );
    }
    my $pub_key = $self->oidc->get_public_key($key_id);

    # Build JWKS with our federation key
    my $jwk =
      $self->buildFederationJwk( $pub_key->{public}, $pub_key->{external_id} );

    # Build OIDC provider metadata (reuse existing metadata generation)
    my $issuer          = $self->oidc->get_issuer($req);
    my $provider_metadata = $self->oidc->metadataDoc($issuer);

    # Build Entity Configuration payload
    my $now     = time();
    my $payload = {
        iss              => $entity_id,
        sub              => $entity_id,
        iat              => $now,
        exp              => $now + 86400,    # 24h validity
        jwks             => { keys => [$jwk] },
        metadata         => {
            openid_provider => $provider_metadata,
            federation_entity => {
                federation_fetch_endpoint =>
                  $issuer . '/' . $self->path . '/federation_fetch',
                federation_list_endpoint =>
                  $issuer . '/' . $self->path . '/federation_list',
            },
        },
    };

    # Add authority_hints if configured (space-separated string)
    my $authority_hints_str = $self->conf->{oidcFederationAuthorityHints} || '';
    if ($authority_hints_str) {
        my @hints = split( /\s+/, $authority_hints_str );
        $payload->{authority_hints} = \@hints if @hints;
    }

    # Sign the Entity Configuration
    my $alg = $self->conf->{oidcFederationSigningAlg} || 'RS256';
    my $jwt = $self->signEntityStatement( $payload, $priv_key->{private},
        $pub_key->{external_id}, $alg );
    unless ($jwt) {
        return $self->p->sendError( $req, 'server_error', 500 );
    }

    # Return as application/entity-statement+jwt
    return $self->_sendJWT( $req, $jwt );
}

# Federation fetch endpoint - serves Subordinate Statements about known RPs
sub fetchEndpoint {
    my ( $self, $req ) = @_;

    my $subject = $req->param('sub');
    unless ($subject) {
        return $self->p->sendError( $req, 'Missing sub parameter', 400 );
    }

    # Find the RP by matching its client_id or entity_id
    my $rp = $self->_findRPByEntityId($subject);
    unless ($rp) {
        return $self->p->sendError( $req, 'Unknown entity', 404 );
    }

    my $entity_id = $self->_getEntityId($req);

    # Get signing key
    my $key_id =
      $self->conf->{oidcFederationSigningKey} || 'default-oidc-sig';
    my $priv_key = $self->oidc->get_private_key($key_id);
    my $pub_key  = $self->oidc->get_public_key($key_id);

    # Build Subordinate Statement
    my $now     = time();
    my $rp_opts = $self->oidc->rpOptions->{$rp};

    my $payload = {
        iss => $entity_id,
        sub => $subject,
        iat => $now,
        exp => $now + 86400,
        metadata => {
            openid_relying_party => {
                client_id     => $rp_opts->{oidcRPMetaDataOptionsClientID},
                redirect_uris => $self->_getRPRedirectUris($rp),
            },
        },
    };

    # Add metadata_policy if configured
    my $policy = $self->conf->{oidcFederationMetadataPolicy};
    if ($policy) {
        $payload->{metadata_policy} = $policy;
    }

    my $alg = $self->conf->{oidcFederationSigningAlg} || 'RS256';
    my $jwt = $self->signEntityStatement( $payload, $priv_key->{private},
        $pub_key->{external_id}, $alg );
    unless ($jwt) {
        return $self->p->sendError( $req, 'server_error', 500 );
    }

    return $self->_sendJWT( $req, $jwt );
}

# Federation list endpoint - lists subordinate entity IDs
sub listEndpoint {
    my ( $self, $req ) = @_;

    my @entities;

    # List all known RPs that have federation entity IDs
    my $rp_options = $self->oidc->rpOptions;
    for my $rp ( keys %$rp_options ) {
        my $entity_id =
          $rp_options->{$rp}->{oidcRPMetaDataOptionsFederationEntityId};
        push @entities, $entity_id if $entity_id;
    }

    return $self->p->sendJSONresponse( $req, \@entities );
}

### HOOKS

# Add federation-related fields to OIDC discovery metadata
sub addFederationMetadata {
    my ( $self, $req, $metadata ) = @_;

    $metadata->{client_registration_types_supported} =
      [ 'automatic', 'explicit' ];

    return PE_OK;
}

# Resolve an unknown RP via federation trust chain
sub resolveRPFromFederation {
    my ( $self, $req, $client_id, $config ) = @_;

    # Only act if client_id looks like a URL (entity identifier)
    return PE_OK unless $client_id && $client_id =~ m{^https?://};

    $self->logger->debug(
        "Attempting federation trust chain resolution for $client_id");

    # Resolve the trust chain
    my $chain =
      $self->resolveTrustChain( $client_id, $self->trustAnchors );
    return PE_OK unless $chain;

    $self->logger->notice(
        "Trust chain resolved for $client_id (length: " . scalar(@$chain) . ")"
    );

    # Apply metadata policies to get final RP metadata
    my $rp_metadata =
      $self->applyMetadataPolicy( $chain, 'openid_relying_party' );
    return PE_OK unless $rp_metadata;

    # Build a virtual RP configuration
    my $confKey = 'federation-' . $client_id;
    $confKey =~ s/[^a-zA-Z0-9_-]/_/g;

    $config->{confKey} = $confKey;
    $config->{options} = {
        oidcRPMetaDataOptionsClientID => $rp_metadata->{client_id}
          || $client_id,
        oidcRPMetaDataOptionsRedirectUris =>
          join( ' ', @{ $rp_metadata->{redirect_uris} || [] } ),
        oidcRPMetaDataOptionsIDTokenSignAlg =>
          $rp_metadata->{id_token_signed_response_alg} || 'RS256',
        oidcRPMetaDataOptionsAccessTokenSignAlg =>
          $rp_metadata->{access_token_signed_response_alg} || 'RS256',
        oidcRPMetaDataOptionsDisplayName =>
          $rp_metadata->{client_name} || $client_id,
        oidcRPMetaDataOptionsFederationEntityId => $client_id,
    };

    # Token endpoint auth method
    if ( $rp_metadata->{token_endpoint_auth_method} ) {
        my %auth_map = (
            'client_secret_post'  => 'client_secret_post',
            'client_secret_basic' => 'client_secret_basic',
            'private_key_jwt'     => 'private_key_jwt',
            'none'                => 'none',
        );
        $config->{options}->{oidcRPMetaDataOptionsAuthentication} =
          $auth_map{ $rp_metadata->{token_endpoint_auth_method} } || '';
    }

    # Grant types
    if ( $rp_metadata->{grant_types} ) {
        my %grants = map { $_ => 1 } @{ $rp_metadata->{grant_types} };
        $config->{options}->{oidcRPMetaDataOptionsAllowOffline} =
          $grants{'refresh_token'} ? 1 : 0;
    }

    # Response types
    if ( $rp_metadata->{response_types} ) {
        $config->{options}->{oidcRPMetaDataOptionsAllowedResponseTypes} =
          join( ', ', @{ $rp_metadata->{response_types} } );
    }

    $config->{ttl} = 3600;    # Cache for 1 hour

    return PE_OK;
}

# Check if incoming registration request comes from a federated entity
sub federationRegistrationCheck {
    my ( $self, $req, $client_metadata ) = @_;

    # Look for a trust_chain in the registration request
    my $trust_chain_jwt = $client_metadata->{trust_chain};
    return PE_OK unless $trust_chain_jwt;

    $self->logger->debug("Registration request with trust_chain detected");

    # Validate the trust chain
    my $entity_id = $client_metadata->{client_id}
      || $client_metadata->{entity_id};
    return PE_OK unless $entity_id;

    my $chain =
      $self->resolveTrustChain( $entity_id, $self->trustAnchors );
    if ($chain) {
        $self->logger->notice(
            "Federation registration approved for $entity_id");
        $req->data->{federationChain}    = $chain;
        $req->data->{federationEntityId} = $entity_id;
        return PE_DONE;    # Allow registration even if globally disabled
    }

    $self->logger->warn(
        "Federation registration denied: no valid trust chain for $entity_id");
    return PE_OK;
}

# Customize registration response for federated RPs
sub federationRegistrationResponse {
    my ( $self, $req, $registration_state ) = @_;

    my $entity_id = $req->data->{federationEntityId};
    return PE_OK unless $entity_id;

    my $chain = $req->data->{federationChain};
    return PE_OK unless $chain;

    # Apply metadata policies to determine RP options
    my $rp_metadata =
      $self->applyMetadataPolicy( $chain, 'openid_relying_party' );

    if ($rp_metadata) {

        # Use entity_id as client_id for federated RPs
        $registration_state->{client_id} = $entity_id;

        # For private_key_jwt auth, no client_secret needed
        if (   $rp_metadata->{token_endpoint_auth_method}
            && $rp_metadata->{token_endpoint_auth_method} eq 'private_key_jwt' )
        {
            $registration_state->{client_secret} = undef;
        }

        # Store federation info in RP options
        $registration_state->{rp_options}
          ->{oidcRPMetaDataOptionsFederationEntityId} = $entity_id;
    }

    return PE_OK;
}

### INTERNAL METHODS

sub _getEntityId {
    my ( $self, $req ) = @_;
    return $self->conf->{oidcFederationEntityId}
      || $self->oidc->get_issuer($req);
}

sub _findRPByEntityId {
    my ( $self, $entity_id ) = @_;
    my $rp_options = $self->oidc->rpOptions;
    for my $rp ( keys %$rp_options ) {
        if (
            (
                   $rp_options->{$rp}->{oidcRPMetaDataOptionsFederationEntityId}
                || ''
            ) eq $entity_id
            || ( $rp_options->{$rp}->{oidcRPMetaDataOptionsClientID} || '' ) eq
            $entity_id
          )
        {
            return $rp;
        }
    }
    return;
}

sub _getRPRedirectUris {
    my ( $self, $rp ) = @_;
    my $uris =
      $self->conf->{oidcRPMetaDataOptions}->{$rp}
      ->{oidcRPMetaDataOptionsRedirectUris} || '';
    return [ split( /\s+/, $uris ) ];
}

sub _sendJWT {
    my ( $self, $req, $jwt ) = @_;
    return [
        200,
        [
            'Content-Type'   => 'application/entity-statement+jwt',
            'Content-Length' => length($jwt),
            $req->spliceHdrs,
        ],
        [$jwt]
    ];
}

1;
