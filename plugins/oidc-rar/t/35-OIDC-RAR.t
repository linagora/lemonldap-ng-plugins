use warnings;
use Test::More;
use strict;
use IO::String;
use MIME::Base64 qw/encode_base64 decode_base64url/;
use Encode qw/encode/;
use URI::Escape qw/uri_escape_utf8/;
use JSON;
use Lemonldap::NG::Portal::Main::Request;

# Skip the PAR + RAR end-to-end subtest when oidc-par's lib hasn't been
# linked alongside oidc-rar (it's only linked when the test was prepared
# with `with: ["oidc-par"]`). All other subtests run unconditionally.
my $par_available =
  eval { require Lemonldap::NG::Portal::Plugins::OIDCPushedAuthRequest; 1 };

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my ( $op, $res );

ok( $op = register( 'op', sub { op() } ), 'OP portal' );

my $id = login( $op, "french" );

my %base_authorize = (
    response_type => "code",
    scope         => "openid profile",
    state         => "af0ifjsldkj",
    redirect_uri  => "http://rp.com/",
);

my $valid_details = encode_json( [ {
        type             => "payment_initiation",
        instructedAmount => { currency => "EUR", amount => "100.00" },
} ] );

subtest "Discovery advertises authorization_details_types_supported" => sub {
    my $res = $op->_get(
        "/.well-known/openid-configuration",
        accept => 'application/json',
    );
    my $json = expectJSON($res);
    ok( $json->{authorization_details_types_supported},
        "authorization_details_types_supported is present" );
    is_deeply(
        [ sort @{ $json->{authorization_details_types_supported} } ],
        [ "account_information", "payment_initiation" ],
        "supported types are correct"
    );
};

subtest "Valid authorization_details echoed in token response" => sub {
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp",
            authorization_details => $valid_details,
        }
    );
    my ($code) = expectRedirection( $auth_res, qr#http://.*code=([^\&]*)# );
    ok( $code, "Authorization code received" );

    my $token_res = expectJSON(
        codeGrant( $op, "rp", $code, "http://rp.com/" )
    );
    ok( $token_res->{authorization_details},
        "authorization_details echoed in token response" );
    is( $token_res->{authorization_details}->[0]->{type},
        "payment_initiation", "echoed type matches" );
    is( $token_res->{authorization_details}->[0]->{instructedAmount}
          ->{amount},
        "100.00", "echoed payload matches" );
};

subtest "JWT access token carries authorization_details claim" => sub {
    my $code = codeAuthorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp",
            authorization_details => $valid_details,
        }
    );
    my $token_res = expectJSON(
        codeGrant( $op, "rp", $code, "http://rp.com/" )
    );
    my $payload = getJWTPayload( $token_res->{access_token} );
    ok( $payload, "Access token is a JWT" );
    ok( $payload->{authorization_details},
        "authorization_details claim present in JWT" );
    is( $payload->{authorization_details}->[0]->{type},
        "payment_initiation", "claim type matches" );
};

subtest "Introspection includes authorization_details" => sub {
    my $code = codeAuthorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp",
            authorization_details => $valid_details,
        }
    );
    my $token_res = expectJSON(
        codeGrant( $op, "rp", $code, "http://rp.com/" )
    );
    my $intro = expectJSON(
        introspect( $op, "rp", $token_res->{access_token} ) );
    ok( $intro->{authorization_details},
        "authorization_details present in introspection" );
    is( $intro->{authorization_details}->[0]->{type},
        "payment_initiation", "introspected type matches" );
};

subtest "Refresh token preserves authorization_details" => sub {
    my $code = codeAuthorize(
        $op, $id,
        {
            %base_authorize,
            scope                 => "openid profile offline_access",
            client_id             => "rp",
            authorization_details => $valid_details,
        }
    );
    my $token_res = expectJSON(
        codeGrant( $op, "rp", $code, "http://rp.com/" )
    );
    ok( $token_res->{refresh_token}, "refresh_token issued" );

    my $query = buildForm( {
            grant_type    => "refresh_token",
            refresh_token => $token_res->{refresh_token},
    } );
    my $refresh_res = $op->_post(
        "/oauth2/token",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
        custom => {
            HTTP_AUTHORIZATION => "Basic " . encode_base64( "rp:rp", '' ),
        },
    );
    my $refresh_json = expectJSON($refresh_res);
    ok( $refresh_json->{authorization_details},
        "refresh response includes authorization_details" );
    is( $refresh_json->{authorization_details}->[0]->{type},
        "payment_initiation", "refresh keeps original type" );
};

subtest "Type not in allowlist is rejected" => sub {
    my $bad = encode_json( [ { type => "ride_hailing" } ] );
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp",
            authorization_details => $bad,
        }
    );
    expectPortalError( $auth_res, 24,
        "type outside allowlist returns portal error" );
};

subtest "Malformed JSON is rejected" => sub {
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp",
            authorization_details => "not_json{",
        }
    );
    expectPortalError( $auth_res, 24,
        "malformed JSON returns portal error" );
};

subtest "Detail missing `type` is rejected" => sub {
    my $bad = encode_json( [ { foo => "bar" } ] );
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp",
            authorization_details => $bad,
        }
    );
    expectPortalError( $auth_res, 24,
        "detail without `type` returns portal error" );
};

subtest "Perl rule rejects detail when condition fails" => sub {
    # rp_strict has a rule requiring detail->{instructedAmount}{amount} <= 50
    my $over = encode_json( [ {
            type             => "payment_initiation",
            instructedAmount => { currency => "EUR", amount => "9999.00" },
    } ] );
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp_strict",
            authorization_details => $over,
        }
    );
    expectPortalError( $auth_res, 24,
        "rule rejection returns portal error" );
};

subtest "Perl rule is enforced on implicit and hybrid flows" => sub {
    my $over = encode_json( [ {
            type             => "payment_initiation",
            instructedAmount => { currency => "EUR", amount => "9999.00" },
    } ] );
    my %params = (
        scope                 => "openid",
        client_id             => "rp_strict",
        authorization_details => $over,
        state                 => "s",
        nonce                 => "n",
        redirect_uri          => "http://rp.com/",
        # Must not be usable to skip the rule from the authorize URL.
        grant_type => "x",
    );

    # Implicit: the rule rejection stops the token; the core returns an
    # OIDC error redirect instead of an access token.
    my $auth_res = authorize(
        $op, $id,
        {
            %params,
            response_type => 'id_token token',
        }
    );
    my ($loc) = expectRedirection( $auth_res, qr#(http://rp\.com/.*)# );
    like( $loc, qr/error=server_error/, "implicit: rule rejection" );
    unlike( $loc, qr/access_token=/, "implicit: no access token" );

    # Hybrid: the core creates the code before any plugin hook, so the code
    # is issued. It carries no authorization_details, and exchanging it gives
    # a token without the refused rights.
    $auth_res = authorize(
        $op, $id,
        {
            %params,
            response_type => 'code id_token',
        }
    );
    my ($code) = expectRedirection( $auth_res, qr#http://.*code=([^\&]*)# );
    ok( $code, "hybrid: code issued" );
    my $token_res =
      expectJSON( codeGrant( $op, "rp_strict", $code, "http://rp.com/" ) );
    ok( !$token_res->{authorization_details},
        "hybrid: no refused authorization_details in the token" );
};

subtest "Perl rule grants detail when condition holds" => sub {
    my $ok_detail = encode_json( [ {
            type             => "payment_initiation",
            instructedAmount => { currency => "EUR", amount => "10.00" },
    } ] );
    my $code = codeAuthorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp_strict",
            authorization_details => $ok_detail,
        }
    );
    my $token_res = expectJSON(
        codeGrant( $op, "rp_strict", $code, "http://rp.com/" )
    );
    ok( $token_res->{authorization_details},
        "small payment is granted by rule" );
};

subtest "Uncompilable Perl rule fails closed (deny-all)" => sub {
    # rp_badrule has a syntactically broken rule; the plugin must install a
    # deny-all fallback rather than silently dropping the rule (which would
    # weaken authorization).
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp_badrule",
            authorization_details => $valid_details,
        }
    );
    expectPortalError( $auth_res, 24,
        "broken rule denies all RAR requests for the RP" );
};

subtest "RP without RAR enabled rejects authorization_details" => sub {
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id             => "rp_norar",
            authorization_details => $valid_details,
        }
    );
    expectPortalError( $auth_res, 24,
        "RAR-disabled RP returns portal error when details are sent" );
};

subtest "Consent template variable is HTML-escaped (XSS prevention)" => sub {
    my $plugin = $op->p->loadedModules->{
        'Lemonldap::NG::Portal::Plugins::OIDCRichAuthRequest' };
    ok( $plugin, "RAR plugin is loaded" );

    my $req = Lemonldap::NG::Portal::Main::Request->new( {} );
    $req->data->{_rar_details} = [ {
            type => "payment_initiation",
            note => '<script>alert(1)</script>',
            html => '<img src=x onerror="alert(2)">',
    } ];
    my $tpl  = "oidcGiveConsent";
    my $args = { params => {} };

    $plugin->injectConsentDetails( $req, \$tpl, $args );
    my $out = $args->{params}->{RAR_DETAILS};
    ok( $out, "RAR_DETAILS variable is set" );
    unlike( $out, qr/<script>/,
        "raw <script> tag is not present in the rendered variable" );
    unlike( $out, qr/<img/,
        "raw <img> tag is not present in the rendered variable" );
    like( $out, qr/&lt;script&gt;/, "<script> is HTML-encoded" );
    like( $out, qr/&quot;/,        '" is HTML-encoded' );
};

subtest "Consent injection skips non-consent OIDC templates" => sub {
    my $plugin = $op->p->loadedModules->{
        'Lemonldap::NG::Portal::Plugins::OIDCRichAuthRequest' };
    my $req = Lemonldap::NG::Portal::Main::Request->new( {} );
    $req->data->{_rar_details} = [ { type => "payment_initiation" } ];

    for my $tpl_name (qw/oidcLogout oidcOfflineTokens login/) {
        my $tpl  = $tpl_name;
        my $args = { params => {} };
        $plugin->injectConsentDetails( $req, \$tpl, $args );
        ok( !exists $args->{params}->{RAR_DETAILS},
            "$tpl_name template is left alone" );
    }
};

SKIP: {
    skip "oidc-par not linked (run with: ['oidc-par'])", 1
      unless $par_available;

    subtest "PAR + RAR end-to-end (companion patch in oidc-par)" => sub {
        my $op2 = register( 'op_par_rar', sub { op_par_rar() } );
        ok( $op2, "OP with PAR+RAR loaded" );
        my $id2 = login( $op2, "french" );

        # Push authorization_details through PAR
        my $details = encode_json( [ {
                type             => "payment_initiation",
                instructedAmount => { currency => "EUR", amount => "42.00" },
        } ] );
        my $par_query = buildForm( {
                response_type         => "code",
                scope                 => "openid profile",
                state                 => "par-rar",
                redirect_uri          => "http://rp.com/",
                client_id             => "rp",
                authorization_details => $details,
        } );
        my $par_res = $op2->_post(
            "/oauth2/par",
            IO::String->new($par_query),
            accept => 'application/json',
            length => length($par_query),
            custom => {
                HTTP_AUTHORIZATION => "Basic "
                  . encode_base64( "rp:rp", '' ),
            },
        );
        is( $par_res->[0], 201, "PAR push accepted" );
        my $par_json = from_json( $par_res->[2]->[0] );
        ok( $par_json->{request_uri}, "request_uri returned" );

        # Authorize with the request_uri only
        my $auth_res = authorize(
            $op2, $id2,
            {
                client_id   => "rp",
                request_uri => $par_json->{request_uri},
            }
        );
        my ($code) =
          expectRedirection( $auth_res, qr#http://.*code=([^\&]*)# );
        ok( $code, "Authorization code received through PAR" );

        # Token response must echo authorization_details — the proof the
        # parameter actually flowed: PAR push → PAR session → authorize
        # → code session → token response.
        my $token_res = expectJSON(
            codeGrant( $op2, "rp", $code, "http://rp.com/" )
        );
        ok( $token_res->{authorization_details},
            "authorization_details surfaced in token response" );
        is( $token_res->{authorization_details}->[0]->{type},
            "payment_initiation", "type preserved end-to-end" );
        is(
            $token_res->{authorization_details}->[0]
              ->{instructedAmount}->{amount},
            "42.00",
            "payload preserved end-to-end"
        );

        # Raw UTF-8 goes through the PAR session as bytes flagged as
        # characters; it must not be double-encoded.
        my $raw_detail = do {
            my $note = "\x{263a}\x{e9}";
            qq([{"type":"payment_initiation","note":"$note"}]);
        };
        # Build the PAR body by hand: LLNG 2.23.2's buildForm uses
        # uri_escape(), which warns on characters above U+00FF. The PAR
        # endpoint expects the percent-encoded UTF-8 bytes, so use the
        # UTF-8-aware escaper on the character string.
        my %par_params2 = (
            response_type         => "code",
            scope                 => "openid profile",
            state                 => "par-rar-utf8",
            redirect_uri          => "http://rp.com/",
            client_id             => "rp",
            authorization_details => $raw_detail,
        );
        my $par_query2 =
          join '&',
          map { $_ . '=' . uri_escape_utf8( $par_params2{$_} ) }
          keys %par_params2;
        my $par_res2 = $op2->_post(
            "/oauth2/par",
            IO::String->new($par_query2),
            accept => 'application/json',
            length => length($par_query2),
            custom => {
                HTTP_AUTHORIZATION => "Basic "
                  . encode_base64( "rp:rp", '' ),
            },
        );
        is( $par_res2->[0], 201, "PAR push with raw UTF-8 accepted" );
        my $par_json2 = from_json( $par_res2->[2]->[0] );

        my $auth_res2 = authorize(
            $op2, $id2,
            {
                client_id   => "rp",
                request_uri => $par_json2->{request_uri},
            }
        );
        my ($code2) =
          expectRedirection( $auth_res2, qr#http://.*code=([^\&]*)# );

        my $token_res2 =
          codeGrant( $op2, "rp", $code2, "http://rp.com/" );
        is( $token_res2->[0], 200, "token endpoint answers 200" );
        my $token_json2 = JSON->new->utf8->decode( $token_res2->[2]->[0] );
        is(
            encode( 'UTF-8',
                $token_json2->{authorization_details}->[0]->{note} ),
            encode( 'UTF-8', "\x{263a}\x{e9}" ),
            "raw UTF-8 detail survives the PAR round-trip"
        );
    };

    subtest "PAR without authorization_details ignores a front-channel value" =>
      sub {
        my $op3 = register( 'op_par_rar', sub { op_par_rar() } );
        my $id3 = login( $op3, 'french' );

        my $par_query = buildForm(
            {
                response_type => "code",
                scope         => "openid",
                redirect_uri  => "http://rp.com/",
                client_id     => "rp",
            }
        );
        my $par_res = $op3->_post(
            "/oauth2/par",
            IO::String->new($par_query),
            accept => 'application/json',
            length => length($par_query),
            custom => {
                HTTP_AUTHORIZATION => "Basic "
                  . encode_base64( "rp:rp", '' ),
            },
        );
        is( $par_res->[0], 201, "PAR push without details accepted" );
        my $par_json = from_json( $par_res->[2]->[0] );

        my $auth_res = authorize(
            $op3, $id3,
            {
                client_id             => "rp",
                request_uri           => $par_json->{request_uri},
                authorization_details => $valid_details,
            }
        );
        my ($code) =
          expectRedirection( $auth_res, qr#http://.*code=([^\&]*)# );
        ok( $code, "Authorization code received" );

        my $token_res = expectJSON(
            codeGrant( $op3, "rp", $code, "http://rp.com/" )
        );
        ok( !$token_res->{authorization_details},
            "front-channel authorization_details are ignored" );
      };
}

subtest "Request without authorization_details still works" => sub {
    my $auth_res = authorize(
        $op, $id,
        {
            %base_authorize,
            client_id => "rp",
        }
    );
    my ($code) = expectRedirection( $auth_res, qr#http://.*code=([^\&]*)# );
    ok( $code, "Authorization code received without RAR" );

    my $token_res = expectJSON(
        codeGrant( $op, "rp", $code, "http://rp.com/" )
    );
    ok( $token_res->{access_token}, "Access token received" );
    ok( !$token_res->{authorization_details},
        "no authorization_details in response when not requested" );
};

# Like codeAuthorize(), but escapes the parameters ourselves: LLNG 2.23.2's
# buildForm uses uri_escape(), which warns on characters above U+00FF. The
# endpoint expects percent-encoded UTF-8 bytes, so use the UTF-8-aware escaper.
sub codeAuthorizeUtf8 {
    my ( $op, $id, $params ) = @_;
    my $query =
      join '&',
      map { $_ . '=' . uri_escape_utf8( $params->{$_} ) } keys %$params;
    my $res = $op->_get(
        "/oauth2/authorize",
        query  => $query,
        accept => 'text/html',
        cookie => "lemonldap=$id",
    );
    my ($code) = expectRedirection( $res, qr#http://.*code=([^\&]*)# );
    return $code;
}

for my $case (
    [ 'smiley+accent', "\x{263a}\x{e9}",
      '[{"type":"payment_initiation","note":"\u263a\u00e9"}]' ],
    [ 'accent', "\x{e9}", '[{"type":"payment_initiation","note":"\u00e9"}]' ],
    [ 'raw-utf8', "\x{263a}\x{e9}",
      do {
          my $note = "\x{263a}\x{e9}";
          qq([{"type":"payment_initiation","note":"$note"}]);
      }
    ],
  )
{
    my ( $name, $label, $detail ) = @$case;
    subtest "Non-ASCII detail survives the token endpoint: $name" => sub {
        my $code = codeAuthorizeUtf8(
            $op, $id,
            {
                %base_authorize,
                client_id             => "rp",
                authorization_details => $detail,
            }
        );
        my $token_res = codeGrant( $op, "rp", $code, "http://rp.com/" );
        is( $token_res->[0], 200, "the token endpoint answers 200" );
        my $json = JSON->new->utf8->decode( $token_res->[2]->[0] );
        ok( $json->{authorization_details}, "details echoed in the response" );

        my @parts = split /\./, $json->{access_token};
        my $payload =
          JSON->new->utf8->decode( decode_base64url( $parts[1] ) );
        is( ref $payload, 'HASH', "the access token payload is a JSON object" );
        is_deeply( $payload->{authorization_details},
            $json->{authorization_details},
            "the access token and the response show the same list" );
        is( encode( 'UTF-8', $payload->{authorization_details}->[0]->{note} ),
            encode( 'UTF-8', $label ),
            "the note is decoded correctly" );

        my $intro_res = introspect( $op, "rp", $json->{access_token} );
        is( $intro_res->[0], 200, "introspection answers 200" );
        my $intro = JSON->new->utf8->decode( $intro_res->[2]->[0] );
        is_deeply( $intro->{authorization_details},
            $json->{authorization_details},
            "introspection shows the same list" );
    };
}

{
    package t::RarReq;
    sub data { return $_[0]->{data} ||= {} }
}

subtest "flagged PAR bytes are not double-encoded" => sub {
    my $rar =
      $op->p->loadedModules
      ->{'Lemonldap::NG::Portal::Plugins::OIDCRichAuthRequest'};
    my $bytes = encode( 'UTF-8', "\x{263a}\x{e9}" );
    my $flagged = join '', map { chr($_) } unpack( 'C*', $bytes );
    utf8::upgrade($flagged);
    my $raw = '[{"type":"payment_initiation","note":"' . $flagged . '"}]';

    my $req = bless { data => {} }, 't::RarReq';
    my $oidc_request =
      { client_id => 'rp', authorization_details => $raw };
    is( $rar->parseAuthorizationDetails( $req, $oidc_request ), 0,
        'flagged bytes accepted' );
    is(
        encode( 'UTF-8', $req->data->{_rar_details}->[0]->{note} ),
        encode( 'UTF-8', "\x{263a}\x{e9}" ),
        'the detail is not double-encoded'
    );
};

subtest "invalid UTF-8 bytes are refused" => sub {
    my $rar =
      $op->p->loadedModules
      ->{'Lemonldap::NG::Portal::Plugins::OIDCRichAuthRequest'};
    my $raw = '[{"type":"payment_initiation","note":"' . "\xE9" . '"}]';

    my $req = bless { data => {} }, 't::RarReq';
    my $oidc_request =
      { client_id => 'rp', authorization_details => $raw };
    my $rc = $rar->parseAuthorizationDetails( $req, $oidc_request );
    isnt( $rc, 0, 'invalid UTF-8 bytes are refused' );
    ok( !$req->data->{_rar_details}, 'nothing is stored for invalid UTF-8' );
};

subtest "Consent page escapes non-ASCII details as HTML" => sub {
    my $rar =
      $op->p->loadedModules
      ->{'Lemonldap::NG::Portal::Plugins::OIDCRichAuthRequest'};
    my $req = bless {
        data => {
            _rar_details => [
                { type => 'payment_initiation', note => "\x{e9}\x{263a}" }
            ]
        }
    }, 't::RarReq';
    my $tpl  = 'oidcConsent';
    my $args = { params => {} };
    $rar->injectConsentDetails( $req, \$tpl, $args );
    my $html = $args->{params}->{RAR_DETAILS} || '';
    like( $html, qr/&eacute;/,    'é is escaped as an HTML entity' );
    like( $html, qr/&#x263A;/,   '☺ is escaped as a numeric entity' );
    unlike( $html, qr/&Atilde;/, 'no mojibake entity' );
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
                customPlugins                   => '::Plugins::OIDCRichAuthRequest',
                issuerDBOpenIDConnectActivation => "1",
                restSessionServer               => 1,

                # RAR global allowlist
                oidcServiceAuthorizationDetailsTypes =>
                  'payment_initiation,account_information',

                oidcRPMetaDataExportedVars => {
                    rp         => { email => "mail", name => "cn", groups => "groups" },
                    rp_strict  => { email => "mail", name => "cn", groups => "groups" },
                    rp_norar   => { email => "mail", name => "cn", groups => "groups" },
                    rp_badrule => { email => "mail", name => "cn", groups => "groups" },
                },
                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcServiceAllowImplicitFlow          => 1,
                oidcServiceAllowHybridFlow            => 1,
                oidcServiceAllowOffline               => 1,
                oidcRPMetaDataOptions                 => {
                    rp => {
                        oidcRPMetaDataOptionsDisplayName            => "RP",
                        oidcRPMetaDataOptionsIDTokenExpiration      => 3600,
                        oidcRPMetaDataOptionsClientID               => "rp",
                        oidcRPMetaDataOptionsClientSecret           => "rp",
                        oidcRPMetaDataOptionsIDTokenSignAlg         => "RS256",
                        oidcRPMetaDataOptionsBypassConsent          => 1,
                        oidcRPMetaDataOptionsAccessTokenExpiration  => 3600,
                        oidcRPMetaDataOptionsAccessTokenJWT         => 1,
                        oidcRPMetaDataOptionsAccessTokenSignAlg     => "RS256",
                        oidcRPMetaDataOptionsRedirectUris           => 'http://rp.com/',
                        oidcRPMetaDataOptionsAllowOffline           => 1,
                        oidcRPMetaDataOptionsAuthorizationDetailsEnabled => 1,
                        oidcRPMetaDataOptionsAuthorizationDetailsTypes =>
                          'payment_initiation,account_information',
                    },
                    rp_strict => {
                        oidcRPMetaDataOptionsDisplayName            => "RP Strict",
                        oidcRPMetaDataOptionsIDTokenExpiration      => 3600,
                        oidcRPMetaDataOptionsClientID               => "rp_strict",
                        oidcRPMetaDataOptionsClientSecret           => "rp_strict",
                        oidcRPMetaDataOptionsIDTokenSignAlg         => "RS256",
                        oidcRPMetaDataOptionsBypassConsent          => 1,
                        oidcRPMetaDataOptionsAccessTokenExpiration  => 3600,
                        oidcRPMetaDataOptionsAccessTokenJWT         => 1,
                        oidcRPMetaDataOptionsAccessTokenSignAlg     => "RS256",
                        oidcRPMetaDataOptionsRedirectUris           => 'http://rp.com/',
                        oidcRPMetaDataOptionsAuthorizationDetailsEnabled => 1,
                        oidcRPMetaDataOptionsAuthorizationDetailsTypes =>
                          'payment_initiation',
                        # Only allow payments up to 50 EUR
                        oidcRPMetaDataOptionsAuthorizationDetailsRules =>
                          '{"payment_initiation": "$detail->{instructedAmount}->{amount} <= 50"}',
                    },
                    rp_norar => {
                        oidcRPMetaDataOptionsDisplayName            => "RP NoRAR",
                        oidcRPMetaDataOptionsIDTokenExpiration      => 3600,
                        oidcRPMetaDataOptionsClientID               => "rp_norar",
                        oidcRPMetaDataOptionsClientSecret           => "rp_norar",
                        oidcRPMetaDataOptionsIDTokenSignAlg         => "RS256",
                        oidcRPMetaDataOptionsBypassConsent          => 1,
                        oidcRPMetaDataOptionsAccessTokenExpiration  => 3600,
                        oidcRPMetaDataOptionsRedirectUris           => 'http://rp.com/',
                        # RAR disabled
                    },
                    rp_badrule => {
                        oidcRPMetaDataOptionsDisplayName            => "RP BadRule",
                        oidcRPMetaDataOptionsIDTokenExpiration      => 3600,
                        oidcRPMetaDataOptionsClientID               => "rp_badrule",
                        oidcRPMetaDataOptionsClientSecret           => "rp_badrule",
                        oidcRPMetaDataOptionsIDTokenSignAlg         => "RS256",
                        oidcRPMetaDataOptionsBypassConsent          => 1,
                        oidcRPMetaDataOptionsAccessTokenExpiration  => 3600,
                        oidcRPMetaDataOptionsRedirectUris           => 'http://rp.com/',
                        oidcRPMetaDataOptionsAuthorizationDetailsEnabled => 1,
                        # Syntactically broken Perl: must trigger fail-closed
                        oidcRPMetaDataOptionsAuthorizationDetailsRules =>
                          '{"payment_initiation": "this is not valid perl (("}',
                    },
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            }
        }
    );
}

# Config used by the "PAR + RAR end-to-end" subtest. Loads both plugins and
# enables RAR + PAR on a single RP, so a `resource` push that carries
# `authorization_details` can be observed all the way to the token response.
sub op_par_rar {
    return LLNG::Manager::Test->new( {
            ini => {
                domain                          => 'idp.com',
                portal                          => 'http://auth.op.com/',
                authentication                  => 'Demo',
                userDB                          => 'Same',
                customPlugins                   =>
                  '::Plugins::OIDCPushedAuthRequest, '
                  . '::Plugins::OIDCRichAuthRequest',
                issuerDBOpenIDConnectActivation => "1",
                restSessionServer               => 1,

                oidcServiceMetaDataPushedAuthURI => 'par',
                oidcServicePushedAuthExpiration  => 60,

                oidcRPMetaDataExportedVars => {
                    rp => { email => "mail", name => "cn", groups => "groups" },
                },
                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcRPMetaDataOptions                 => {
                    rp => {
                        oidcRPMetaDataOptionsDisplayName           => "RP",
                        oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                        oidcRPMetaDataOptionsClientID              => "rp",
                        oidcRPMetaDataOptionsClientSecret          => "rp",
                        oidcRPMetaDataOptionsIDTokenSignAlg        => "RS256",
                        oidcRPMetaDataOptionsBypassConsent         => 1,
                        oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                        oidcRPMetaDataOptionsRedirectUris    => 'http://rp.com/',
                        oidcRPMetaDataOptionsPAR             => 'allowed',
                        oidcRPMetaDataOptionsAuthorizationDetailsEnabled => 1,
                        oidcRPMetaDataOptionsAuthorizationDetailsTypes   =>
                          'payment_initiation',
                    },
                },
                oidcServicePrivateKeySig => oidc_key_op_private_sig,
                oidcServicePublicKeySig  => oidc_cert_op_public_sig,
            }
        }
    );
}
