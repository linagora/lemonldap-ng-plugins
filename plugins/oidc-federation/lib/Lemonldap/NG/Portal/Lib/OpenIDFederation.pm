package Lemonldap::NG::Portal::Lib::OpenIDFederation;

use strict;
use Mouse::Role;
use Crypt::JWT qw(encode_jwt decode_jwt);
use JSON       qw(from_json to_json);
use Lemonldap::NG::Common::UserAgent;

our $VERSION = '2.21.0';

requires qw(conf logger p);

has ua => (
    is      => 'rw',
    lazy    => 1,
    builder => sub {
        my $ua = Lemonldap::NG::Common::UserAgent->new( $_[0]->{conf} );
        $ua->env_proxy();
        return $ua;
    }
);

# Build and sign an Entity Statement JWT
# @param payload HashRef of claims
# @param private_key PEM private key
# @param key_id optional kid
# @param alg signing algorithm (default RS256)
# @return signed JWT string
sub signEntityStatement {
    my ( $self, $payload, $private_key, $key_id, $alg ) = @_;
    $alg //= 'RS256';

    my $extra_headers = { typ => 'entity-statement+jwt' };
    $extra_headers->{kid} = $key_id if $key_id;

    my $jwt = eval {
        encode_jwt(
            payload       => to_json($payload),
            alg           => $alg,
            key           => \$private_key,
            extra_headers => $extra_headers,
        );
    };
    if ($@) {
        $self->logger->error("Failed to sign Entity Statement: $@");
        return;
    }
    return $jwt;
}

# Build JWKS from a PEM public key
# @param public_key PEM public key or certificate
# @param key_id optional kid
# @param key_type 'RSA' or 'EC' (auto-detected if undef)
# @return HashRef JWK
sub buildFederationJwk {
    my ( $self, $public_key, $key_id, $key_type ) = @_;

    $key_type //= $self->_detectKeyType($public_key);
    my $jwk;

    if ( $key_type eq 'EC' ) {
        require Crypt::PK::ECC;
        my $pk = Crypt::PK::ECC->new();
        $pk->import_key( \$public_key );
        $jwk = $pk->export_key_jwk( 'public', 1 );
    }
    else {
        require Crypt::PK::RSA;
        my $pk = Crypt::PK::RSA->new();
        $pk->import_key( \$public_key );
        $jwk = $pk->export_key_jwk( 'public', 1 );
    }

    $jwk->{kid} = $key_id if $key_id;
    $jwk->{use} = 'sig';
    return $jwk;
}

# Fetch and decode an Entity Configuration from a remote entity
# @param entity_id the entity identifier (URL)
# @return HashRef decoded payload, or undef on failure
sub fetchEntityConfiguration {
    my ( $self, $entity_id ) = @_;

    # Entity Configuration is at entity_id/.well-known/openid-federation
    my $url = $entity_id;
    $url =~ s|/+$||;
    $url .= '/.well-known/openid-federation';

    $self->logger->debug("Fetching Entity Configuration from $url");

    my $response = $self->ua->get($url);
    unless ( $response->is_success ) {
        $self->logger->error(
            "Failed to fetch Entity Configuration from $url: "
              . $response->status_line );
        return;
    }

    return $self->_decodeEntityStatement( $response->decoded_content );
}

# Fetch a Subordinate Statement from a superior's fetch endpoint
# @param fetch_endpoint the superior's federation_fetch_endpoint URL
# @param subject the subordinate entity ID
# @param superior_jwks ArrayRef of JWK hashes for signature verification
# @return HashRef decoded payload, or undef on failure
sub fetchSubordinateStatement {
    my ( $self, $fetch_endpoint, $subject, $superior_jwks ) = @_;

    my $url = $fetch_endpoint . '?sub=' . $subject;
    $self->logger->debug("Fetching Subordinate Statement from $url");

    my $response = $self->ua->get($url);
    unless ( $response->is_success ) {
        $self->logger->error(
            "Failed to fetch Subordinate Statement from $url: "
              . $response->status_line );
        return;
    }

    return $self->_decodeEntityStatement( $response->decoded_content,
        $superior_jwks );
}

# Resolve a trust chain from a leaf entity to a trust anchor
# @param entity_id the leaf entity ID
# @param trust_anchors HashRef { entity_id => { jwks => [...] } }
# @param max_depth maximum chain length (default 10)
# @return ArrayRef of Entity Statement payloads (leaf to anchor), or undef
sub resolveTrustChain {
    my ( $self, $entity_id, $trust_anchors, $max_depth ) = @_;
    $max_depth //= 10;

    # Step 1: fetch the leaf's Entity Configuration
    my $leaf_config = $self->fetchEntityConfiguration($entity_id);
    unless ($leaf_config) {
        $self->logger->error(
            "Trust chain resolution failed: cannot fetch $entity_id");
        return;
    }

    # Check if this entity is directly a trust anchor
    if ( $trust_anchors->{$entity_id} ) {
        return [$leaf_config];
    }

    my $authority_hints = $leaf_config->{authority_hints};
    unless ( $authority_hints
        && ref($authority_hints) eq 'ARRAY'
        && @$authority_hints )
    {
        $self->logger->error(
            "Trust chain resolution failed: $entity_id has no authority_hints");
        return;
    }

    # Step 2: walk up authority_hints
    for my $superior_id (@$authority_hints) {
        my $chain = $self->_walkTrustChain(
            $entity_id,     $leaf_config, $superior_id,
            $trust_anchors, $max_depth - 1
        );
        return $chain if $chain;
    }

    $self->logger->error(
"Trust chain resolution failed: no path to a trust anchor from $entity_id"
    );
    return;
}

sub _walkTrustChain {
    my ( $self, $subject_id, $subject_config, $superior_id, $trust_anchors,
        $depth )
      = @_;

    return if $depth <= 0;

    # Fetch the superior's Entity Configuration
    my $superior_config = $self->fetchEntityConfiguration($superior_id);
    return unless $superior_config;

    my $superior_jwks = $superior_config->{jwks}->{keys};
    return unless $superior_jwks && ref($superior_jwks) eq 'ARRAY';

    # The superior must have a federation_fetch_endpoint
    my $fetch_endpoint =
      $superior_config->{metadata}->{federation_entity}
      ->{federation_fetch_endpoint};
    unless ($fetch_endpoint) {
        $self->logger->error(
            "Superior $superior_id has no federation_fetch_endpoint");
        return;
    }

    # Fetch the Subordinate Statement about the subject
    my $sub_statement =
      $self->fetchSubordinateStatement( $fetch_endpoint, $subject_id,
        $superior_jwks );
    return unless $sub_statement;

    # Build chain so far: [leaf_config, subordinate_statement]
    my @chain = ( $subject_config, $sub_statement );

    # Check if the superior is a trust anchor
    if ( $trust_anchors->{$superior_id} ) {
        push @chain, $superior_config;
        return \@chain;
    }

    # Otherwise, recurse up
    my $superior_hints = $superior_config->{authority_hints};
    if ( $superior_hints && ref($superior_hints) eq 'ARRAY' ) {
        for my $next_superior_id (@$superior_hints) {
            my $upper_chain = $self->_walkTrustChain(
                $superior_id,   $superior_config, $next_superior_id,
                $trust_anchors, $depth - 1
            );
            if ($upper_chain) {

                # Prepend our portion
                return [ $subject_config, $sub_statement, @$upper_chain ];
            }
        }
    }

    return;
}

# Apply metadata policies from a trust chain
# The chain is ordered: leaf, subordinate statements..., trust anchor
# Each subordinate statement may contain metadata_policy
# @param chain ArrayRef of entity statement payloads
# @param entity_type e.g. 'openid_relying_party', 'openid_provider'
# @return HashRef final metadata after policy application, or undef
sub applyMetadataPolicy {
    my ( $self, $chain, $entity_type ) = @_;

    # Start with the leaf's own metadata
    my $leaf     = $chain->[0];
    my $metadata = $leaf->{metadata}->{$entity_type};
    unless ($metadata) {
        $self->logger->error("Leaf entity has no metadata for $entity_type");
        return;
    }

    # Deep copy to avoid modifying original
    $metadata = from_json( to_json($metadata) );

    # Apply policies from each statement in the chain (skip leaf at index 0)
    for my $i ( 1 .. $#$chain ) {
        my $statement = $chain->[$i];
        my $policy    = $statement->{metadata_policy}->{$entity_type};
        next unless $policy && ref($policy) eq 'HASH';

        $self->_applyPolicy( $metadata, $policy );
    }

    return $metadata;
}

# Apply a single level of metadata policy to metadata
sub _applyPolicy {
    my ( $self, $metadata, $policy ) = @_;

    for my $claim ( keys %$policy ) {
        my $operators = $policy->{$claim};
        next unless ref($operators) eq 'HASH';

        # 'value' operator: override the claim value
        if ( exists $operators->{value} ) {
            $metadata->{$claim} = $operators->{value};
        }

        # 'default' operator: set if not present
        if ( exists $operators->{default} && !exists $metadata->{$claim} ) {
            $metadata->{$claim} = $operators->{default};
        }

        # 'one_of' operator: value must be one of the listed values
        if ( exists $operators->{one_of} && exists $metadata->{$claim} ) {
            my %allowed = map { $_ => 1 } @{ $operators->{one_of} };
            unless ( $allowed{ $metadata->{$claim} } ) {
                $self->logger->warn(
                    "Policy violation: $claim value not in one_of");
                delete $metadata->{$claim};
            }
        }

        # 'subset_of' operator: all values must be in the allowed set
        if ( exists $operators->{subset_of} && exists $metadata->{$claim} ) {
            if ( ref( $metadata->{$claim} ) eq 'ARRAY' ) {
                my %allowed = map { $_ => 1 } @{ $operators->{subset_of} };
                $metadata->{$claim} =
                  [ grep { $allowed{$_} } @{ $metadata->{$claim} } ];
            }
        }

        # 'superset_of' operator: must contain all required values
        if ( exists $operators->{superset_of} && exists $metadata->{$claim} ) {
            if ( ref( $metadata->{$claim} ) eq 'ARRAY' ) {
                my %has = map { $_ => 1 } @{ $metadata->{$claim} };
                for my $required ( @{ $operators->{superset_of} } ) {
                    unless ( $has{$required} ) {
                        push @{ $metadata->{$claim} }, $required;
                    }
                }
            }
        }

        # 'add' operator: add values to an array claim
        if ( exists $operators->{add} && exists $metadata->{$claim} ) {
            if ( ref( $metadata->{$claim} ) eq 'ARRAY' ) {
                my %has = map { $_ => 1 } @{ $metadata->{$claim} };
                for my $val ( @{ $operators->{add} } ) {
                    push @{ $metadata->{$claim} }, $val unless $has{$val};
                }
            }
        }

        # 'essential' operator: claim must be present
        if ( $operators->{essential} && !exists $metadata->{$claim} ) {
            $self->logger->error(
                "Policy violation: essential claim $claim is missing");
            return;
        }
    }

    return 1;
}

# Decode and optionally verify an entity statement JWT
# @param jwt_string the raw JWT
# @param jwks optional ArrayRef of JWK hashes for verification
# @return HashRef payload, or undef
sub _decodeEntityStatement {
    my ( $self, $jwt_string, $jwks ) = @_;

    # Remove whitespace
    $jwt_string =~ s/\s//g;

    my $payload;
    if ($jwks) {

        # Verify signature against provided JWKS
        $payload = eval {
            decode_jwt(
                token    => $jwt_string,
                kid_keys => { keys => $jwks },
            );
        };
    }
    else {
        # Self-signed: extract payload first, then verify with embedded JWKS
        $payload =
          eval { decode_jwt( token => $jwt_string, ignore_signature => 1, ); };

        if ( $payload && ref($payload) eq 'HASH' ) {

            # Re-parse as string if needed
            $payload = from_json($payload) if !ref($payload);

            if ( my $embedded_jwks = $payload->{jwks} ) {

                # Re-verify with the embedded keys
                eval {
                    decode_jwt(
                        token    => $jwt_string,
                        kid_keys => $embedded_jwks,
                    );
                };
                if ($@) {
                    $self->logger->error(
"Entity Statement self-signature verification failed: $@"
                    );
                    return;
                }
            }
        }
    }

    if ($@) {
        $self->logger->error("Failed to decode Entity Statement: $@");
        return;
    }

    # Handle JSON string payload (Crypt::JWT may return string)
    if ( $payload && !ref($payload) ) {
        $payload = eval { from_json($payload) };
        if ($@) {
            $self->logger->error("Invalid Entity Statement payload JSON: $@");
            return;
        }
    }

    return $payload;
}

sub _detectKeyType {
    my ( $self, $key_pem ) = @_;
    if ( $key_pem =~ /EC/ ) {
        return 'EC';
    }
    return 'RSA';
}

1;
