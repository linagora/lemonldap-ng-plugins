package Lemonldap::NG::Portal::Lib::OpenIDFederation;

use strict;
use Mouse::Role;
use Crypt::JWT qw(encode_jwt decode_jwt);
use JSON       qw(from_json to_json);
use URI;
use Lemonldap::NG::Common::UserAgent;

our $VERSION = '2.21.0';

requires qw(conf logger p);

# Hard limits for one resolution: a malicious chain can branch at every
# level, so bound both the number of hints explored and the total fetches.
use constant MAX_AUTHORITY_HINTS => 5;
use constant MAX_FETCHES         => 20;
use constant MAX_RESPONSE_SIZE   => 512 * 1024;

has _chainCache => ( is => 'rw', default => sub { {} } );

has ua => (
    is      => 'rw',
    lazy    => 1,
    builder => sub {
        my ($self) = @_;
        my $timeout = $self->conf->{oidcFederationFetchTimeout} || 5;

        # Federation resolution is triggered by unauthenticated callers: do
        # not let them reach loopback, private or link-local addresses.
        if ( $self->conf->{oidcFederationAllowPrivateHosts} ) {
            my $ua = Lemonldap::NG::Common::UserAgent->new( $self->{conf} );
            $ua->env_proxy();
            $ua->timeout($timeout);
            $ua->max_size(MAX_RESPONSE_SIZE);
            return $ua;
        }

        require LWPx::ParanoidAgent;
        my %args = (
            timeout  => $timeout,
            max_size => MAX_RESPONSE_SIZE,
            agent    => "LemonLDAP-NG/$Lemonldap::NG::Portal::Main::VERSION ",
        );
        $args{ssl_opts} = $self->conf->{lwpSslOpts}
          if ref $self->conf->{lwpSslOpts} eq 'HASH';
        my $ua = LWPx::ParanoidAgent->new(%args);

        # Shared address space (RFC 6598), often used inside clusters
        $ua->blocked_hosts( qr/^100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./ );
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

# An OpenID Federation entity identifier is an https URL without query or
# fragment (OpenID Federation 1.0 §1.2). Fetch endpoints follow the same rule.
sub isSecureUrl {
    my ( $self, $url ) = @_;
    return 0 unless defined $url && !ref $url && length $url;
    my $uri = eval { URI->new($url) };
    return 0 unless $uri;
    return 0 unless defined $uri->scheme && lc( $uri->scheme ) eq 'https';
    return 0 unless defined $uri->host && length $uri->host;
    return 0 if defined $uri->userinfo;
    return 0 if defined $uri->query;
    return 0 if defined $uri->fragment;
    return 1;
}

sub _fetchJwt {
    my ( $self, $url, $what, $budget ) = @_;
    $what ||= 'statement';

    my $timeout = $self->conf->{oidcFederationFetchTimeout} || 5;
    if ( ref $budget eq 'HASH' && $budget->{deadline} ) {
        my $remaining = $budget->{deadline} - time;
        return if $remaining <= 0;
        $timeout = $remaining if $remaining < $timeout;
    }

    $self->logger->debug("Fetching $what from $url");
    my $ua = $self->ua;
    $ua->timeout($timeout);

    my $response = $ua->get($url);
    if ( $response->header('Client-Aborted') || $response->header('X-Died') ) {
        $self->logger->error(
            "Failed to fetch $what from $url: response aborted");
        return;
    }
    unless ( $response->is_success ) {
        $self->logger->error(
            "Failed to fetch $what from $url: " . $response->status_line );
        return;
    }
    return $response->decoded_content;
}

sub _fetchEntityConfigurationJwt {
    my ( $self, $entity_id, $budget ) = @_;
    return unless $self->isSecureUrl($entity_id);

    my $url = $entity_id;
    $url =~ s|/+$||;
    $url .= '/.well-known/openid-federation';
    return $self->_fetchJwt( $url, 'Entity Configuration', $budget );
}

# Fetch and decode an Entity Configuration from a remote entity
# @param entity_id the entity identifier (URL)
# @param jwks optional JWKS to verify it (required for a trust anchor)
# @return HashRef decoded payload, or undef on failure
sub fetchEntityConfiguration {
    my ( $self, $entity_id, $jwks, $budget ) = @_;
    my $jwt = $self->_fetchEntityConfigurationJwt( $entity_id, $budget );
    return unless defined $jwt;
    return $self->_decodeEntityStatement( $jwt, $jwks );
}

# Fetch a Subordinate Statement from a superior's fetch endpoint
# @param fetch_endpoint the superior's federation_fetch_endpoint URL
# @param subject the subordinate entity ID
# @param superior_jwks ArrayRef of JWK hashes for signature verification
# @return HashRef decoded payload, or undef on failure
sub fetchSubordinateStatement {
    my ( $self, $fetch_endpoint, $subject, $superior_jwks, $budget ) = @_;

    return unless $self->isSecureUrl($fetch_endpoint);
    return unless $self->isSecureUrl($subject);
    return unless ref $superior_jwks eq 'ARRAY' && @$superior_jwks;

    # The subject is an entity identifier chosen by the client: encode it,
    # never concatenate it as a raw query value.
    my $uri = URI->new($fetch_endpoint);
    $uri->query_form( sub => $subject );
    my $jwt =
      $self->_fetchJwt( $uri->as_string, 'Subordinate Statement', $budget );
    return unless defined $jwt;
    return $self->_decodeEntityStatement( $jwt, $superior_jwks );
}

# Return the configured JWKS of a trust anchor, or undef when it has none.
sub _anchorJwks {
    my ( $self, $trust_anchors, $entity_id ) = @_;
    return unless ref $trust_anchors eq 'HASH';
    my $anchor = $trust_anchors->{$entity_id};
    return unless ref $anchor eq 'HASH';
    my $jwks = $anchor->{jwks};
    return unless ref $jwks eq 'HASH' && ref $jwks->{keys} eq 'ARRAY';
    my @keys = grep { ref $_ eq 'HASH' } @{ $jwks->{keys} };
    return unless @keys;
    return \@keys;
}

# Check the linkage and lifetime of an Entity Statement.
sub _statementValid {
    my ( $self, $statement, $expected_iss, $expected_sub ) = @_;

    return 0 unless ref $statement eq 'HASH';

    for my $check ( [ iss => $expected_iss ], [ sub => $expected_sub ] ) {
        my ( $claim, $expected ) = @$check;
        next unless defined $expected;
        return 0
          unless defined $statement->{$claim}
          && !ref $statement->{$claim}
          && $statement->{$claim} eq $expected;
    }

    my $now  = time;
    my $skew = 30;

    my $exp = $statement->{exp};
    return 0
      unless defined $exp
      && !ref $exp
      && $exp =~ /\A-?[0-9]+(?:\.[0-9]+)?\z/
      && $exp + $skew > $now;

    if ( defined $statement->{iat} ) {
        my $iat = $statement->{iat};
        return 0
          if ref $iat
          || $iat !~ /\A-?[0-9]+(?:\.[0-9]+)?\z/
          || $iat - $skew > $now;
    }

    return 1;
}

# Resolve a trust chain from a leaf entity to a trust anchor
# @param entity_id the leaf entity ID
# @param trust_anchors HashRef { entity_id => { jwks => ... } }
# @param max_depth maximum chain length (default 10)
# @return ArrayRef of Entity Statement payloads (leaf to anchor), or undef
sub resolveTrustChain {
    my ( $self, $entity_id, $trust_anchors, $max_depth ) = @_;

    my $ttl = $self->conf->{oidcFederationCacheTTL} // 60;
    if ( $ttl > 0 ) {
        # The key is the entity ID only: both callers use the same trust
        # anchors and depth, and a configuration reload replaces the plugin.
        my $cached = $self->_chainCache->{$entity_id};
        return $cached->{chain} if $cached && time < $cached->{expire};
    }

    my $chain =
      $self->_resolveTrustChain( $entity_id, $trust_anchors, $max_depth );

    if ( $ttl > 0 ) {
        my $expire = time + $ttl;
        if ( ref $chain eq 'ARRAY' ) {
            for my $statement (@$chain) {
                next unless ref $statement eq 'HASH';
                my $exp = $statement->{exp};
                next unless defined $exp && !ref $exp;
                $expire = $exp if $exp < $expire;
            }
        }
        my $cache = $self->_chainCache;
        $cache->{$entity_id} = { expire => $expire, chain => $chain };

        # Keep the cache bounded without letting new entries flush it.
        if ( keys %$cache > 1000 ) {
            my @oldest =
              sort { $cache->{$a}{expire} <=> $cache->{$b}{expire} }
              keys %$cache;
            my $drop = @oldest - 1000;
            delete @$cache{ @oldest[ 0 .. $drop - 1 ] } if $drop > 0;
        }
    }

    return $chain;
}

# Consume the fetch budget of one resolution.
sub _consumeBudget {
    my ( $self, $budget, $count ) = @_;
    return 0 unless ref $budget eq 'HASH';
    return 0 if $budget->{deadline} && time >= $budget->{deadline};
    $budget->{left} -= $count;
    return $budget->{left} >= 0;
}

# Authority hints to explore: valid https URLs only, capped per level.
sub _candidateHints {
    my ( $self, $hints ) = @_;
    return unless ref $hints eq 'ARRAY';
    my @valid = grep { $self->isSecureUrl($_) } @$hints;
    @valid = @valid[ 0 .. MAX_AUTHORITY_HINTS - 1 ]
      if @valid > MAX_AUTHORITY_HINTS;
    return @valid;
}

sub _resolveTrustChain {
    my ( $self, $entity_id, $trust_anchors, $max_depth ) = @_;
    $max_depth //= 10;

    return unless $self->isSecureUrl($entity_id);

    my $deadline =
      time + ( $self->conf->{oidcFederationResolutionTimeout} // 15 );
    my $budget = { left => MAX_FETCHES, deadline => $deadline };
    return unless $self->_consumeBudget( $budget, 1 );

    my $is_anchor =
      ref $trust_anchors eq 'HASH' && exists $trust_anchors->{$entity_id};
    my $anchor_jwks = $self->_anchorJwks( $trust_anchors, $entity_id );
    return if $is_anchor && !$anchor_jwks;

    # Step 1: fetch the leaf's Entity Configuration
    my $leaf_jwt = $self->_fetchEntityConfigurationJwt( $entity_id, $budget );
    return unless defined $leaf_jwt;
    my $leaf_config = $self->_decodeEntityStatement( $leaf_jwt, $anchor_jwks );
    unless ( $leaf_config
        && $self->_statementValid( $leaf_config, $entity_id, $entity_id ) )
    {
        $self->logger->error(
            "Trust chain resolution failed: invalid Entity Configuration for "
              . $entity_id );
        return;
    }

    # A trust anchor is its own chain.
    return [$leaf_config] if $is_anchor;

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
    for my $superior_id ( $self->_candidateHints($authority_hints) ) {
        my $chain = $self->_walkTrustChain(
            $entity_id,    $leaf_jwt, $superior_id,
            $trust_anchors, $max_depth - 1, $budget
        );
        return $chain if $chain;
    }

    $self->logger->error(
"Trust chain resolution failed: no path to a trust anchor from $entity_id"
    );
    return;
}

sub _walkTrustChain {
    my ( $self, $subject_id, $subject_jwt, $superior_id, $trust_anchors,
        $depth, $budget )
      = @_;

    return if $depth <= 0;
    return unless $self->isSecureUrl($superior_id);
    return unless $self->_consumeBudget( $budget, 2 );

    my $is_anchor =
      ref $trust_anchors eq 'HASH' && exists $trust_anchors->{$superior_id};
    my $anchor_jwks = $self->_anchorJwks( $trust_anchors, $superior_id );
    return if $is_anchor && !$anchor_jwks;

    # Fetch and verify the superior's Entity Configuration. A trust anchor is
    # verified with the keys already configured, not with its self-published
    # JWKS.
    my $superior_jwt =
      $self->_fetchEntityConfigurationJwt( $superior_id, $budget );
    return unless defined $superior_jwt;
    my $superior_config =
      $self->_decodeEntityStatement( $superior_jwt, $anchor_jwks );
    unless ( $superior_config
        && $self->_statementValid( $superior_config, $superior_id,
            $superior_id ) )
    {
        $self->logger->error(
                "Trust chain resolution failed: invalid Entity Configuration "
              . "for superior $superior_id" );
        return;
    }

    # Keys that must have signed the Subordinate Statement.
    my $superior_jwks = $anchor_jwks;
    unless ($superior_jwks) {
        my $published = $superior_config->{jwks};
        return
          unless ref $published eq 'HASH'
          && ref $published->{keys} eq 'ARRAY';
        my @keys = grep { ref $_ eq 'HASH' } @{ $published->{keys} };
        return unless @keys;
        $superior_jwks = \@keys;
    }

    # The superior must have a federation_fetch_endpoint
    my $metadata = $superior_config->{metadata};
    return unless ref $metadata eq 'HASH';
    my $federation_entity = $metadata->{federation_entity};
    return unless ref $federation_entity eq 'HASH';
    my $fetch_endpoint = $federation_entity->{federation_fetch_endpoint};
    unless ( $self->isSecureUrl($fetch_endpoint) ) {
        $self->logger->error(
            "Superior $superior_id has no usable federation_fetch_endpoint");
        return;
    }

    # Fetch the Subordinate Statement about the subject
    my $sub_statement = $self->fetchSubordinateStatement(
        $fetch_endpoint, $subject_id, $superior_jwks, $budget );
    return unless $sub_statement;
    unless (
        $self->_statementValid( $sub_statement, $superior_id, $subject_id ) )
    {
        $self->logger->error(
"Trust chain resolution failed: Subordinate Statement from $superior_id does not vouch for $subject_id"
        );
        return;
    }

    # The superior vouches for the subject's keys: verify the subject's Entity
    # Configuration against them.
    my $vouched = $sub_statement->{jwks};
    return unless ref $vouched eq 'HASH' && ref $vouched->{keys} eq 'ARRAY';
    my @vouched_keys = grep { ref $_ eq 'HASH' } @{ $vouched->{keys} };
    return unless @vouched_keys;
    my $verified_subject =
      $self->_decodeEntityStatement( $subject_jwt, \@vouched_keys );
    unless ( $verified_subject
        && $self->_statementValid( $verified_subject, $subject_id,
            $subject_id ) )
    {
        $self->logger->error(
"Trust chain resolution failed: $subject_id is not signed by the keys $superior_id vouched for"
        );
        return;
    }

    # Build chain so far: [leaf_config, subordinate_statement]
    my @chain = ( $verified_subject, $sub_statement );

    # A trust anchor ends the chain.
    if ($is_anchor) {
        push @chain, $superior_config;
        return \@chain;
    }

    # Otherwise, recurse up
    my $superior_hints = $superior_config->{authority_hints};
    if ( $superior_hints && ref($superior_hints) eq 'ARRAY' ) {
        for my $next_superior_id ( $self->_candidateHints($superior_hints) ) {
            my $upper_chain = $self->_walkTrustChain(
                $superior_id,   $superior_jwt, $next_superior_id,
                $trust_anchors, $depth - 1,    $budget
            );
            if ($upper_chain) {

                # Prepend our portion
                return [ $verified_subject, $sub_statement, @$upper_chain ];
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

    return unless ref $chain eq 'ARRAY' && ref $chain->[0] eq 'HASH';

    # Start with the leaf's own metadata
    my $leaf = $chain->[0];
    my $leaf_metadata = $leaf->{metadata};
    return unless ref $leaf_metadata eq 'HASH';
    my $metadata = $leaf_metadata->{$entity_type};
    unless ( ref $metadata eq 'HASH' ) {
        $self->logger->error("Leaf entity has no metadata for $entity_type");
        return;
    }

    # Deep copy to avoid modifying original
    $metadata = from_json( to_json($metadata) );

    # Apply policies from each statement in the chain (skip leaf at index 0)
    for my $i ( 1 .. $#$chain ) {
        my $statement = $chain->[$i];
        next unless ref $statement eq 'HASH';
        next unless exists $statement->{metadata_policy};
        my $statements = $statement->{metadata_policy};
        return unless ref $statements eq 'HASH';
        next unless exists $statements->{$entity_type};
        my $policy = $statements->{$entity_type};
        return unless ref $policy eq 'HASH';

        return unless $self->_applyPolicy( $metadata, $policy );
    }

    return $metadata;
}

# Apply a single level of metadata policy to metadata
sub _applyPolicy {
    my ( $self, $metadata, $policy ) = @_;

    return unless ref $metadata eq 'HASH' && ref $policy eq 'HASH';

    for my $claim ( keys %$policy ) {
        my $operators = $policy->{$claim};
        next unless ref($operators) eq 'HASH';

        # Operators taking a list of values must actually hold one; refusing
        # the whole policy is safer than dereferencing a scalar.
        for my $operator (qw(one_of subset_of superset_of add)) {
            next unless exists $operators->{$operator};
            unless ( ref $operators->{$operator} eq 'ARRAY' ) {
                $self->logger->error(
                    "Policy operator $operator for $claim must be an array");
                return;
            }
            if ( grep { ref $_ } @{ $operators->{$operator} } ) {
                $self->logger->error(
                    "Policy operator $operator for $claim must hold scalars");
                return;
            }
        }

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
                return;
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

        # 'superset_of' operator: must already contain all required values
        if ( exists $operators->{superset_of} && exists $metadata->{$claim} ) {
            unless ( ref( $metadata->{$claim} ) eq 'ARRAY' ) {
                $self->logger->warn(
                    "Policy violation: $claim is not an array for superset_of"
                );
                return;
            }
            my %has = map { $_ => 1 } @{ $metadata->{$claim} };
            for my $required ( @{ $operators->{superset_of} } ) {
                unless ( $has{$required} ) {
                    $self->logger->warn(
"Policy violation: $claim does not contain required value $required"
                    );
                    return;
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

    return unless defined $jwt_string && !ref $jwt_string;

    # Remove whitespace
    $jwt_string =~ s/\s//g;
    return unless length $jwt_string;

    my $payload;
    if ($jwks) {

        # Verify signature against provided JWKS
        $payload = eval {
            decode_jwt(
                token    => $jwt_string,
                kid_keys => { keys => $jwks },
            );
        };
        if ($@) {
            $self->logger->error("Failed to decode Entity Statement: $@");
            return;
        }
    }
    else {

        # Self-signed: extract payload first, then verify with embedded JWKS
        $payload =
          eval { decode_jwt( token => $jwt_string, ignore_signature => 1, ); };
        if ($@) {
            $self->logger->error("Failed to decode Entity Statement: $@");
            return;
        }

        if ( $payload && !ref $payload ) {
            $payload = eval { from_json($payload) };
            if ($@) {
                $self->logger->error(
                    "Invalid Entity Statement payload JSON: $@");
                return;
            }
        }

        unless ( ref $payload eq 'HASH' ) {
            $self->logger->error(
                'Entity Statement payload is not a JSON object');
            return;
        }

        my $embedded_jwks = $payload->{jwks};
        unless ( ref $embedded_jwks eq 'HASH'
            && ref $embedded_jwks->{keys} eq 'ARRAY'
            && @{ $embedded_jwks->{keys} } )
        {
            $self->logger->error(
                'Entity Configuration has no usable jwks');
            return;
        }

        # Re-verify with the embedded keys
        eval {
            decode_jwt(
                token    => $jwt_string,
                kid_keys => $embedded_jwks,
            );
        };
        if ($@) {
            $self->logger->error(
                "Entity Statement self-signature verification failed: $@");
            return;
        }
    }

    # Handle JSON string payload (Crypt::JWT may return string)
    if ( $payload && !ref $payload ) {
        $payload = eval { from_json($payload) };
        if ($@) {
            $self->logger->error("Invalid Entity Statement payload JSON: $@");
            return;
        }
    }

    unless ( ref $payload eq 'HASH' ) {
        $self->logger->error(
            'Entity Statement payload is not a JSON object');
        return;
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
