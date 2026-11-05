package Lemonldap::NG::Portal::Plugins::OpenIDFederation;

use strict;
use Mouse;
use JSON qw(from_json to_json);
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
);

our $VERSION = '2.21.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

with 'Lemonldap::NG::Portal::Lib::OpenIDFederation';

use constant hook => {
    oidcGenerateMetadata       => 'addFederationMetadata',
    getOidcRpConfig            => 'resolveRPFromFederation',
    oidcGotRegistrationRequest => 'federationRegistrationCheck',
    oidcRegisterClient         => 'federationRegisterClient',
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

    # Fail at startup rather than on the first unauthenticated resolution.
    unless ( $self->conf->{oidcFederationAllowPrivateHosts} ) {
        eval { require LWPx::ParanoidAgent; 1 } or do {
            $self->logger->error(
                'LWPx::ParanoidAgent is required unless '
                  . 'oidcFederationAllowPrivateHosts is set' );
            return 0;
        };
    }

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

    # Only act if client_id is an entity identifier: https, no query or
    # fragment.
    return PE_OK unless $self->isSecureUrl($client_id);

    $self->logger->debug(
        "Attempting federation trust chain resolution for $client_id");

    # Resolve the trust chain. Remote statements are untrusted input: keep a
    # last-resort barrier so a malformed one cannot turn into a 500.
    my $chain =
      eval { $self->resolveTrustChain( $client_id, $self->trustAnchors ) };
    if ($@) {
        $self->logger->error(
            "Trust chain resolution failed for $client_id: $@");
        return PE_OK;
    }
    return PE_OK unless $chain;

    $self->logger->notice(
        "Trust chain resolved for $client_id (length: " . scalar(@$chain) . ")"
    );

    # Apply metadata policies to get final RP metadata
    my $rp_metadata =
      eval { $self->applyMetadataPolicy( $chain, 'openid_relying_party' ) };
    if ($@) {
        $self->logger->error(
            "Metadata policy failed for $client_id: $@");
        return PE_OK;
    }
    return PE_OK unless ref $rp_metadata eq 'HASH';

    # Reject metadata of the wrong JSON type before building any option.
    for my $key (
        qw(client_id client_name id_token_signed_response_alg
        access_token_signed_response_alg token_endpoint_auth_method)
      )
    {
        next unless exists $rp_metadata->{$key};
        return PE_OK if ref $rp_metadata->{$key};
    }
    for my $key (qw(redirect_uris response_types grant_types)) {
        next unless exists $rp_metadata->{$key};
        return PE_OK unless $self->_stringArray( $rp_metadata->{$key} );
    }

    # Build a virtual RP configuration
    my $confKey = $self->_federationConfKey($client_id);

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
        my $method =
          $auth_map{ $rp_metadata->{token_endpoint_auth_method} } || '';
        $config->{options}->{oidcRPMetaDataOptionsAuthMethod} = $method;

        if ( $method eq 'private_key_jwt' ) {
            my $entity_jwks = $chain->[0]->{jwks};
            $config->{options}->{oidcRPMetaDataOptionsJwks} =
              to_json($entity_jwks)
              if ref $entity_jwks eq 'HASH';
        }
    }

    # Grant types
    if ( $rp_metadata->{grant_types} ) {
        my %grants = map { $_ => 1 } @{ $rp_metadata->{grant_types} };
        $config->{options}->{oidcRPMetaDataOptionsAllowOffline} =
          $grants{'refresh_token'} ? 1 : 0;
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

    # Federated clients must authenticate with the entity key. Ignoring a
    # different request value would make the response inconsistent with the
    # saved configuration.
    my $requested_auth = $client_metadata->{token_endpoint_auth_method} || '';
    unless ( $requested_auth eq 'private_key_jwt' ) {
        $self->logger->error(
            'Federation registration must request private_key_jwt');
        return PE_ERROR;
    }

    # Validate the trust chain
    my $entity_id = $client_metadata->{client_id}
      || $client_metadata->{entity_id};
    unless ($entity_id) {
        $self->logger->warn(
            'Federation registration without client_id or entity_id');
        return PE_ERROR;
    }

    my $chain =
      eval { $self->resolveTrustChain( $entity_id, $self->trustAnchors ) };
    if ($@) {
        $self->logger->error(
            "Federation registration trust chain failed for $entity_id: $@");
        return PE_ERROR;
    }
    unless ($chain) {
        $self->logger->warn(
            "Federation registration denied: no valid trust chain for $entity_id"
        );
        return PE_ERROR;
    }

    my $rp_metadata =
      eval { $self->applyMetadataPolicy( $chain, 'openid_relying_party' ) };
    if ( $@ or !$self->_validFederationMetadata($rp_metadata) ) {
        $self->logger->error(
            "Federation registration metadata for $entity_id is not usable"
              . ( $@ ? ": $@" : '' ) );
        return PE_ERROR;
    }

    if ( my $conflict = $self->_federationRegistrationConflict($entity_id) ) {
        $self->logger->error(
"Federation registration for $entity_id conflicts with existing RP $conflict"
        );
        return PE_ERROR;
    }

    # The core validates and echoes the request metadata: replace it with the
    # policy-applied chain values so the response and the saved RP agree.
    for my $key (qw(redirect_uris client_name id_token_signed_response_alg)) {
        $client_metadata->{$key} = $rp_metadata->{$key}
          if exists $rp_metadata->{$key};
    }
    $client_metadata->{jwks_uri} = $rp_metadata->{jwks_uri}
      if defined $rp_metadata->{jwks_uri}
      && !ref $rp_metadata->{jwks_uri};

    $self->logger->notice(
        "Federation registration approved for $entity_id");
    $req->data->{federationChain}       = $chain;
    $req->data->{federationEntityId}    = $entity_id;
    $req->data->{federationRpMetadata}  = $rp_metadata;

    # Let the core perform the registration; federationRegisterClient builds
    # the RP options from the chain metadata.
    return PE_OK;
}

# Build a federated RP from the trust chain metadata only. The request body
# is never used for options: a valid chain only proves the entity exists, not
# that the caller controls it. Federated clients must authenticate with the
# entity key, so no client secret is issued.
sub federationRegisterClient {
    my ( $self, $req, $newRp, $client_metadata ) = @_;

    my $chain = $req->data->{federationChain};
    return PE_OK unless $chain;
    my $entity_id = $req->data->{federationEntityId};
    return PE_ERROR unless $entity_id;

    my $rp_metadata = $req->data->{federationRpMetadata};
    return PE_ERROR unless $self->_validFederationMetadata($rp_metadata);

    my $entity_jwks = $chain->[0]->{jwks};
    unless ( ref $entity_jwks eq 'HASH'
        && ref $entity_jwks->{keys} eq 'ARRAY'
        && @{ $entity_jwks->{keys} } )
    {
        $self->logger->error(
            "Federation registration for $entity_id has no usable jwks");
        return PE_ERROR;
    }

    if ( my $conflict = $self->_federationRegistrationConflict($entity_id) ) {
        $self->logger->error(
"Federation registration for $entity_id conflicts with existing RP $conflict"
        );
        return PE_ERROR;
    }

    # Only reuse an entry created by federated registration. Merge onto it so
    # admin tweaks (rule, consent, ...) survive a re-registration.
    my $existing = $self->_federatedRP($entity_id);
    my $confKey  = $existing || $self->_federationConfKey($entity_id);
    my $previous = $existing ? ( $self->oidc->rpOptions->{$existing} || {} ) : {};

    my %options = (
        %$previous,
        oidcRPMetaDataOptionsClientID => $entity_id,
        oidcRPMetaDataOptionsRedirectUris =>
          join( ' ', @{ $rp_metadata->{redirect_uris} || [] } ),
        oidcRPMetaDataOptionsIDTokenSignAlg =>
          $rp_metadata->{id_token_signed_response_alg} || 'RS256',
        oidcRPMetaDataOptionsAccessTokenSignAlg =>
          $rp_metadata->{access_token_signed_response_alg} || 'RS256',
        oidcRPMetaDataOptionsDisplayName =>
          $rp_metadata->{client_name} || $entity_id,
        oidcRPMetaDataOptionsFederationEntityId => $entity_id,
        oidcRPMetaDataOptionsAuthMethod => 'private_key_jwt',
        oidcRPMetaDataOptionsJwks       => to_json($entity_jwks),
    );
    if ( $rp_metadata->{grant_types} ) {
        my %grants = map { $_ => 1 } @{ $rp_metadata->{grant_types} };
        $options{oidcRPMetaDataOptionsAllowOffline} =
          $grants{'refresh_token'} ? 1 : 0;
    }

    # A federated client must never receive a secret.
    delete $options{oidcRPMetaDataOptionsClientSecret};
    delete $options{oidcRPMetaDataOptionsPublic};

    $newRp->{confKey} = $confKey;
    $newRp->{options} = \%options;

    if ($existing) {
        my $oidc = $self->oidc;
        $newRp->{attributes} = $oidc->rpAttributes->{$existing}
          if $oidc->rpAttributes->{$existing};
        $newRp->{macros}     = $oidc->rpMacros->{$existing}     || {};
        $newRp->{scopeRules} = $oidc->rpScopeRules->{$existing} || {};
        $newRp->{extraClaims} =
          $self->conf->{oidcRPMetaDataOptionsExtraClaims}->{$existing} || {};
    }

    return PE_OK;
}

### INTERNAL METHODS

sub _getEntityId {
    my ( $self, $req ) = @_;
    return $self->conf->{oidcFederationEntityId}
      || $self->oidc->get_issuer($req);
}

# Federated registration only accepts clients that authenticate with the
# entity keys. The request body is ignored for these fields.
sub _validFederationMetadata {
    my ( $self, $rp_metadata ) = @_;
    return 0 unless ref $rp_metadata eq 'HASH';
    return 0
      unless ( $rp_metadata->{token_endpoint_auth_method} || '' ) eq
      'private_key_jwt';

    for my $key (
        qw(client_id client_name id_token_signed_response_alg
        access_token_signed_response_alg)
      )
    {
        return 0 if exists $rp_metadata->{$key} && ref $rp_metadata->{$key};
    }
    for my $key (qw(redirect_uris response_types grant_types)) {
        return 0
          if exists $rp_metadata->{$key}
          && !$self->_stringArray( $rp_metadata->{$key} );
    }
    return 1;
}

sub _federatedRP {
    my ( $self, $entity_id ) = @_;
    for my $rp ( keys %{ $self->oidc->rpOptions || {} } ) {
        my $opts = $self->oidc->rpOptions->{$rp} || {};
        return $rp
          if ( $opts->{oidcRPMetaDataOptionsFederationEntityId} || '' ) eq
          $entity_id;
    }
    return;
}

# Return the RP that already uses this entity ID without being a federated
# entry for it. Registering would overwrite an admin configuration.
sub _federationRegistrationConflict {
    my ( $self, $entity_id ) = @_;

    for my $rp ( keys %{ $self->oidc->rpOptions || {} } ) {
        my $opts = $self->oidc->rpOptions->{$rp} || {};
        next
          unless ( $opts->{oidcRPMetaDataOptionsClientID} || '' ) eq $entity_id;
        my $fed = $opts->{oidcRPMetaDataOptionsFederationEntityId} || '';
        return $rp unless $fed eq $entity_id;
    }

    my $key  = $self->_federationConfKey($entity_id);
    my $opts = $self->oidc->rpOptions->{$key};
    if ( ref $opts eq 'HASH' ) {
        my $fed = $opts->{oidcRPMetaDataOptionsFederationEntityId} || '';
        return $key unless $fed eq $entity_id;
    }

    return;
}

sub _federationConfKey {
    my ( $self, $entity_id ) = @_;
    my $key = 'federation-' . $entity_id;
    $key =~ s/[^a-zA-Z0-9_-]/_/g;
    return $key;
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

# A metadata claim that must hold a list of non-empty strings.
sub _stringArray {
    my ( $self, $value ) = @_;
    return 0 unless ref $value eq 'ARRAY';
    return 0 if grep { !defined $_ || ref $_ || !length $_ } @$value;
    return 1;
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
