package Lemonldap::NG::Portal::Plugins::OIDCResourceIndicators;

# RFC 8707: Resource Indicators for OAuth 2.0
#
# Provider-side implementation. Lets clients name target Resource Server(s)
# on /authorize and /token via the `resource` parameter, evaluates per-RS
# scope rules, and binds issued tokens (JWT `aud`, introspection, refresh)
# to the resolved RS identifiers.

use strict;
use Mouse;
use Lemonldap::NG::Portal::Main::Constants qw(PE_OK);
use Lemonldap::NG::Common::JWT qw(getAccessTokenSessionId);

our $VERSION = '2.23.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

# All hooks listed here exist in LLNG >= 2.23. The draft for #3542 used a
# new core hook `oidcGenerateAccessTokenSession`; here we substitute it
# with a post-hoc patch via `oidcGenerateTokenResponse` + `updateToken`,
# which keeps the plugin pure-userland (no core change required).
use constant hook => {
    oidcGotRequest                    => 'captureResourceParam',
    oidcGotTokenRequest               => 'handleTokenRequest',
    oidcGotOnlineRefresh              => 'handleRefreshRSScopes',
    oidcGotOfflineRefresh             => 'handleRefreshRSScopes',
    oidcResolveScope                  => 'evaluateRSScopes',
    oidcGenerateCode                  => 'storeRSInCode',
    oidcGenerateRefreshToken          => 'storeRSInRefreshToken',
    oidcGenerateTokenResponse         => 'storeRSInAccessTokenSession',
    oidcGenerateIntrospectionResponse => 'addRSToIntrospection',
    oidcGenerateAccessToken           => 'addAudienceToToken',
};

has _ruleSubs => (
    is      => 'rw',
    isa     => 'HashRef',
    default => sub { {} },
);

# INITIALIZATION - Pre-compile RS scope rules at startup
sub init {
    my ($self) = @_;

    # Validate and pre-compile all RS scope rules
    for my $rp ( keys %{ $self->conf->{oidcRPMetaDataRIScopeRules} || {} } ) {
        my $rules = $self->conf->{oidcRPMetaDataRIScopeRules}->{$rp} || {};
        for my $scope ( keys %$rules ) {
            my $rule = $rules->{$scope};

            # Skip simple rules that don't need compilation
            next if $rule eq '1' || $rule eq '0';
            next if lc($rule) eq 'accept' || lc($rule) eq 'deny';

            # Try to compile the rule
            my $hd         = $self->p->HANDLER;
            my $expression = $hd->substitute($rule);
            my $sub        = $hd->buildSub($expression);

            unless ($sub) {
                my $error = $hd->tsv->{jail}->error || 'Unknown error';
                $self->logger->error(
                    "OIDCResourceIndicators: Invalid rule for RS '$rp' "
                      . "scope '$scope': $rule - $error" );
                return 0;
            }

            # Cache the compiled rule
            $self->_ruleSubs->{$rule} = $sub;
            $self->logger->debug(
                "OIDCResourceIndicators: Pre-compiled rule for RS '$rp' "
                  . "scope '$scope'"
            );
        }
    }

    return $self->SUPER::init;
}

# Hook: Capture the 'resource' parameter on /authorize (RFC 8707)
sub captureResourceParam {
    my ( $self, $req, $oidc_request ) = @_;

    # RFC 8707: resource parameter can appear multiple times.
    # Plack::Request::param returns all values in list context.
    my @resources = $req->param('resource');

    # Also check if it was set in the oidc_request hash
    if ( $oidc_request->{resource} ) {
        my $res = $oidc_request->{resource};
        push @resources, ( ref($res) eq 'ARRAY' ? @$res : ($res) );
    }

    if (@resources) {

        # Remove duplicates
        my %seen;
        @resources = grep { !$seen{$_}++ } @resources;

        $req->data->{rs_audiences} = \@resources;
        $self->logger->debug(
            "OIDCResourceIndicators: Captured resource param: "
              . join( ', ', @resources ) );
    }

    return PE_OK;
}

# Hook: Handle token request - captures resource param for client_credentials
# and restores RS audiences from code session for authorization_code
sub handleTokenRequest {
    my ( $self, $req, $rp, $grant_type ) = @_;

    # For authorization_code: restore rs_audiences from code session
    if ( $grant_type eq 'authorization_code' ) {
        my $code = $req->param('code');
        if ($code) {

            # Read the code session to get stored rs_audiences
            # (code session is not yet consumed at this point)
            my $codeSession = $self->oidc->getAuthorizationCode($code);
            if ( $codeSession && $codeSession->data->{rs_audiences} ) {
                $req->data->{rs_resolved_audiences} =
                  $codeSession->data->{rs_audiences};
                $self->logger->debug(
                    "OIDCResourceIndicators: Restored RS audiences from code: "
                      . join( ', ',
                        @{ $codeSession->data->{rs_audiences} } ) );
            }
        }
    }

    # For client_credentials: capture resource param (possibly multi-valued)
    elsif ( $grant_type eq 'client_credentials' ) {
        my @resources = $req->param('resource');
        if (@resources) {
            my %seen;
            @resources = grep { !$seen{$_}++ } @resources;
            $req->data->{rs_audiences} = \@resources;
            $self->logger->debug(
                "OIDCResourceIndicators: Captured resource param "
                  . "for client_credentials: " . join( ', ', @resources ) );
        }
    }

    return PE_OK;
}

# Hook: Handle RS scopes during refresh token grant
# Called via oidcGotOnlineRefresh or oidcGotOfflineRefresh
sub handleRefreshRSScopes {
    my ( $self, $req, $rp, $session_data, $userData ) = @_;

    # RFC 8707: resource parameter can appear on token endpoint, possibly
    # multi-valued. Plack::Request::param returns all values in list context.
    my @resources = $req->param('resource');
    if (@resources) {
        my %seen;
        @resources = grep { !$seen{$_}++ } @resources;
        $req->data->{rs_audiences} = \@resources;
        $self->logger->debug(
            "OIDCResourceIndicators: Captured resource param for refresh: "
              . join( ', ', @resources ) );
    }

    # If no new resource param, restore from refresh session
    elsif ( my $stored_aud = $session_data->{rs_audiences} ) {
        $req->data->{rs_resolved_audiences} = $stored_aud;
        $self->logger->debug(
            "OIDCResourceIndicators: Restored RS audiences from refresh "
              . "session: " . join( ', ', @$stored_aud ) );
        return PE_OK;
    }

    # Only continue if new resource param was provided
    return PE_OK unless $req->data->{rs_audiences};

    # For online refresh, $userData is passed; for offline, use $session_data
    my $user_info = $userData || $session_data;

    # Temporarily set sessionInfo for rule evaluation. Track whether we
    # actually overrode it so we can restore unconditionally (including
    # restoring the original undef).
    my $had_session_info      = defined $req->sessionInfo;
    my $original_session_info = $req->sessionInfo;
    $req->sessionInfo($user_info) unless $had_session_info;

    # Get scope from session and evaluate RS scopes
    my $scope = $session_data->{scope} || '';
    my @scope_values = split( /\s+/, $scope );

    # Call the same evaluation logic as oidcResolveScope. This may strip
    # denied RS scopes from @scope_values; persist the filtered list back
    # into the refresh session data so downstream token generation uses
    # only granted scopes.
    $self->evaluateRSScopes( $req, \@scope_values, $rp );
    $session_data->{scope} = join( ' ', @scope_values );

    # Restore original sessionInfo, even if it was undef
    $req->sessionInfo($original_session_info) unless $had_session_info;

    return PE_OK;
}

# Hook: Store RS data in authorization code session
sub storeRSInCode {
    my ( $self, $req, $oidc_request, $rp, $code_payload ) = @_;

    if ( my $audiences = $req->data->{rs_resolved_audiences} ) {
        $code_payload->{rs_audiences} = $audiences;
        $self->logger->debug(
            "OIDCResourceIndicators: Stored RS audiences in code session: "
              . join( ', ', @$audiences ) );
    }

    return PE_OK;
}

# Hook: Store RS data in refresh token session
sub storeRSInRefreshToken {
    my ( $self, $req, $refresh_info, $rp, $offline ) = @_;

    if ( my $audiences = $req->data->{rs_resolved_audiences} ) {
        $refresh_info->{rs_audiences} = $audiences;
        $self->logger->debug(
            "OIDCResourceIndicators: Stored RS audiences in refresh token: "
              . join( ', ', @$audiences ) );
    }

    return PE_OK;
}

# Hook: Patch the access token session post-creation, so introspection can
# return the RS audiences. Without `oidcGenerateAccessTokenSession` (which
# the draft for #3542 added in core), we resolve the AT session id from the
# emitted token: getAccessTokenSessionId() handles both JWT (jti) and opaque
# (token == session id) cases.
sub storeRSInAccessTokenSession {
    my ( $self, $req, $rp, $tokensResponse, $oidcSession, $userSession,
        $grant_type )
      = @_;

    my $rs_aud = $req->data->{rs_resolved_audiences};
    return PE_OK unless $rs_aud and @$rs_aud;

    my $token = $tokensResponse->{access_token} or return PE_OK;
    my $at_id = getAccessTokenSessionId($token) or return PE_OK;

    $self->oidc->updateToken( $at_id, { rs_audiences => $rs_aud } );
    $self->logger->debug(
        "OIDCResourceIndicators: Patched AT session $at_id with RS audiences: "
          . join( ', ', @$rs_aud ) );
    return PE_OK;
}

# Hook: Add RS audiences to introspection response
sub addRSToIntrospection {
    my ( $self, $req, $response, $rp, $token_data ) = @_;

    if ( my $rs_aud = $token_data->{rs_audiences} ) {

        # Merge RS audiences into the aud claim
        my $aud = $response->{aud};
        if ($aud) {
            my @all_aud = ref($aud) eq 'ARRAY' ? @$aud : ($aud);
            my %seen = map { $_ => 1 } @all_aud;
            push @all_aud, grep { !$seen{$_}++ } @$rs_aud;
            $response->{aud} = \@all_aud;
        }
        else {
            $response->{aud} = $rs_aud;
        }
        $self->logger->debug(
            "OIDCResourceIndicators: Added RS audiences to introspection: "
              . join( ', ', @$rs_aud ) );
    }

    return PE_OK;
}

# Hook: Evaluate RS scope authorization rules
sub evaluateRSScopes {
    my ( $self, $req, $scopeList, $rp ) = @_;

    my $audiences = $req->data->{rs_audiences} // [];
    return PE_OK unless @$audiences;

    my @resolved_audiences;

    # Track scope decisions per RS
    my %rs_scope_decisions;    # scope => 1 (granted) or 0 (denied)

    for my $aud (@$audiences) {

        # Find the RP corresponding to this audience
        my $rs_rp = $self->_findRPByAudience($aud);
        unless ($rs_rp) {
            $self->logger->debug(
                "OIDCResourceIndicators: No RS found for audience '$aud', "
                  . "ignoring" );
            next;
        }

        push @resolved_audiences, $aud;

        # Get RS scopes and rules from configuration
        my $rs_scopes = $self->conf->{oidcRPMetaDataRIScopes}->{$rs_rp} // {};
        my $rs_rules =
          $self->conf->{oidcRPMetaDataRIScopeRules}->{$rs_rp} // {};

        # Check which requested scopes are RS scopes and evaluate their rules
        for my $scope (@$scopeList) {

            # Only process if this is an RS scope
            next unless exists $rs_scopes->{$scope};

            # Get the rule, default to '1' (always granted)
            my $rule = $rs_rules->{$scope} // '1';

            my $granted = $self->_evaluateRule( $req, $rule, $rs_rp );

            if ($granted) {
                $self->logger->debug(
                    "OIDCResourceIndicators: Granted scope '$scope' for "
                      . "audience '$aud'" );
                $rs_scope_decisions{$scope} //= 1;
            }
            else {
                $self->logger->debug(
                    "OIDCResourceIndicators: Denied scope '$scope' for "
                      . "audience '$aud'" );

                # ANY denial wins (AND logic for security)
                $rs_scope_decisions{$scope} = 0;
            }
        }
    }

    # Now modify the scope list to remove denied RS scopes
    if (%rs_scope_decisions) {
        my @allowed_scopes;
        while (@$scopeList) {
            my $scope = shift(@$scopeList);

            # Keep scope if: not an RS scope, or RS scope that was granted
            if ( !exists $rs_scope_decisions{$scope}
                || $rs_scope_decisions{$scope} )
            {
                push @allowed_scopes, $scope;
            }
            else {
                $self->logger->debug(
                    "OIDCResourceIndicators: Removing denied scope "
                      . "'$scope' from list" );
            }
        }
        push @$scopeList, @allowed_scopes;
    }

    # Store resolved audiences for use in token generation
    $req->data->{rs_resolved_audiences} = \@resolved_audiences
      if @resolved_audiences;

    return PE_OK;
}

# Hook: Add audience to access token JWT payload
sub addAudienceToToken {
    my ( $self, $req, $payload, $rp ) = @_;

    my $audiences = $req->data->{rs_resolved_audiences} // [];
    return PE_OK unless @$audiences;

    # Get current audience from token (should be client_id)
    my $current_aud = $payload->{aud};

    if ($current_aud) {

        # Merge with existing audience
        my @all_aud =
          ref($current_aud) eq 'ARRAY' ? @$current_aud : ($current_aud);
        push @all_aud, @$audiences;

        # Remove duplicates while preserving order
        my %seen;
        @all_aud = grep { !$seen{$_}++ } @all_aud;

        # Set audience (as array if multiple, string if single)
        $payload->{aud} = @all_aud > 1 ? \@all_aud : $all_aud[0];
    }
    else {
        # No existing audience, add RS audiences
        $payload->{aud} = @$audiences > 1 ? $audiences : $audiences->[0];
    }

    $self->logger->debug(
        "OIDCResourceIndicators: Added audiences to token: "
          . join( ', ', @$audiences ) );

    return PE_OK;
}

# Helper: Find an RP by its RS identifier (audience)
sub _findRPByAudience {
    my ( $self, $audience ) = @_;

    for my $rp ( keys %{ $self->conf->{oidcRPMetaDataOptions} || {} } ) {
        my $opts = $self->conf->{oidcRPMetaDataOptions}->{$rp};
        next unless $opts->{oidcRPMetaDataOptionsEnableRI};

        # RS identifier defaults to clientId
        my $rs_id = $opts->{oidcRPMetaDataOptionsRIIdentifier}
          || $opts->{oidcRPMetaDataOptionsClientID};

        return $rp if defined $rs_id && $rs_id eq $audience;
    }

    return;
}

# Helper: Evaluate a Perl rule
sub _evaluateRule {
    my ( $self, $req, $rule, $rp ) = @_;

    # Simple cases
    return 1 if $rule eq '1' || lc($rule) eq 'accept';
    return 0 if $rule eq '0' || lc($rule) eq 'deny';

    # Check cache for compiled sub
    my $sub = $self->_ruleSubs->{$rule};
    unless ($sub) {

        # Build the rule using the portal's handler
        my $hd         = $self->p->HANDLER;
        my $expression = $hd->substitute($rule);
        $sub = $hd->buildSub($expression);

        unless ($sub) {
            $self->logger->error(
                "OIDCResourceIndicators: Invalid rule for RS scope: $rule - "
                  . ( $hd->tsv->{jail}->error || 'Unknown error' ) );
            return 0;
        }

        # Cache the compiled sub
        $self->_ruleSubs->{$rule} = $sub;
    }

    # Evaluate the rule with session data
    my $result = eval { $sub->( $req, $req->sessionInfo ) };
    if ($@) {
        $self->logger->error(
            "OIDCResourceIndicators: Error evaluating rule '$rule': $@");
        return 0;
    }

    return $result ? 1 : 0;
}

1;
