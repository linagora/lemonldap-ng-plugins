package Lemonldap::NG::Portal::Captcha::CaptchEtat;

use strict;
use Mouse;
use JSON;
use Lemonldap::NG::Common::UserAgent;

our $VERSION = '0.1.0';

extends 'Lemonldap::NG::Portal::Main::Plugin';

has ua => (
    is      => 'rw',
    lazy    => 1,
    builder => sub {
        my $ua = Lemonldap::NG::Common::UserAgent->new( $_[0]->{conf} );
        $ua->env_proxy();
        return $ua;
    }
);

has captchaType => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]->{conf}->{captchaOptions}->{captchaType} || 'captchaFR';
    }
);

has apiUrl => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]->{conf}->{captchaOptions}->{apiUrl}
          || (
            $_[0]->{conf}->{captchaOptions}->{sandbox}
            ? 'https://sandbox-api.piste.gouv.fr/piste/captchetat/v2'
            : 'https://api.piste.gouv.fr/piste/captchetat/v2'
          );
    }
);

has oauthUrl => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]->{conf}->{captchaOptions}->{oauthUrl}
          || (
            $_[0]->{conf}->{captchaOptions}->{sandbox}
            ? 'https://sandbox-oauth.piste.gouv.fr/api/oauth/token'
            : 'https://oauth.piste.gouv.fr/api/oauth/token'
          );
    }
);

has timeout => (
    is      => 'rw',
    lazy    => 1,
    default => sub { $_[0]->{conf}->{formTimeout} }
);

has ott => (
    is      => 'rw',
    lazy    => 1,
    default => sub {
        my $ott = $_[0]->{p}->loadModule('::Lib::OneTimeToken');
        $ott->timeout( $_[0]->timeout );
        return $ott;
    }
);

# Cached OAuth2 token
has _accessToken => ( is => 'rw', default => '' );
has _tokenExpiry => ( is => 'rw', default => 0 );

sub init {
    my ($self) = @_;
    unless ( $self->conf->{captchaOptions}->{clientId}
        and $self->conf->{captchaOptions}->{clientSecret} )
    {
        $self->logger->error(
            'CaptchEtat: missing clientId or clientSecret in captchaOptions');
        return 0;
    }
    $self->addUnauthRoute( renewcaptcha      => '_sendCaptcha', ['GET'] );
    $self->addUnauthRoute( captcheatataudio  => '_sendAudio',   ['GET'] );
    return 1;
}

sub _getOAuthToken {
    my ($self) = @_;

    # Return cached token if still valid (with 60s margin)
    if ( $self->_accessToken and time() < $self->_tokenExpiry - 60 ) {
        return $self->_accessToken;
    }

    my $response = $self->ua->post(
        $self->oauthUrl,
        {
            grant_type    => 'client_credentials',
            client_id     => $self->conf->{captchaOptions}->{clientId},
            client_secret => $self->conf->{captchaOptions}->{clientSecret},
            scope         => 'piste.captchetat',
        }
    );

    unless ( $response->is_success ) {
        $self->logger->error(
            'CaptchEtat OAuth error: ' . $response->status_line );
        return;
    }

    my $data = eval { JSON::from_json( $response->decoded_content ) };
    if ($@) {
        $self->logger->error("CaptchEtat OAuth JSON error: $@");
        return;
    }

    $self->_accessToken( $data->{access_token} );
    $self->_tokenExpiry( time() + ( $data->{expires_in} || 3600 ) );

    return $data->{access_token};
}

sub _fetchCaptcha {
    my ($self) = @_;

    my $token = $self->_getOAuthToken;
    unless ($token) {
        $self->logger->error('CaptchEtat: unable to obtain OAuth token');
        return;
    }

    my $url =
        $self->apiUrl
      . '/simple-captcha-endpoint?get=image&c='
      . $self->captchaType;

    my $response = $self->ua->get( $url,
        Authorization => "Bearer $token",
    );

    unless ( $response->is_success ) {
        $self->logger->error(
            'CaptchEtat image error: ' . $response->status_line );
        return;
    }

    my $data = eval { JSON::from_json( $response->decoded_content ) };
    if ($@) {
        $self->logger->error("CaptchEtat image JSON error: $@");
        return;
    }

    unless ( $data->{uuid} and $data->{imageb64} ) {
        $self->logger->error('CaptchEtat: missing uuid or imageb64 in response');
        return;
    }

    my $img      = 'data:image/png;base64,' . $data->{imageb64};
    my $ottToken = $self->ott->createToken( { captchaId => $data->{uuid} } );

    return ( $ottToken, $img );
}

sub _sendCaptcha {
    my ( $self, $req ) = @_;
    $self->logger->info('CaptchEtat: captcha renew requested');
    my ( $token, $image ) = $self->_fetchCaptcha;
    unless ($token) {
        return $self->p->sendError( $req, 'Failed to fetch captcha', 500 );
    }
    return $self->p->sendJSONresponse( $req,
        { newtoken => $token, newimage => $image } );
}

sub _fetchAudio {
    my ( $self, $uuid ) = @_;

    my $token = $self->_getOAuthToken;
    unless ($token) {
        $self->logger->error('CaptchEtat: unable to obtain OAuth token');
        return;
    }

    my $url =
        $self->apiUrl
      . '/simple-captcha-endpoint?get=sound&c='
      . $self->captchaType
      . '&t=' . $uuid;

    my $response = $self->ua->get( $url,
        Authorization => "Bearer $token",
    );

    unless ( $response->is_success ) {
        $self->logger->error(
            'CaptchEtat audio error: ' . $response->status_line );
        return;
    }

    my $data = eval { JSON::from_json( $response->decoded_content ) };
    if ($@) {
        $self->logger->error("CaptchEtat audio JSON error: $@");
        return;
    }

    return $data->{imageb64};
}

sub _sendAudio {
    my ( $self, $req ) = @_;

    my $ottToken = $req->param('token');
    unless ($ottToken) {
        return $self->p->sendError( $req, 'Missing token', 400 );
    }

    # Peek at OTT without consuming it
    my $s = $self->ott->getToken( $ottToken, 1 );
    unless ( $s and $s->{captchaId} ) {
        return $self->p->sendError( $req, 'Invalid token', 400 );
    }

    my $audiob64 = $self->_fetchAudio( $s->{captchaId} );
    unless ($audiob64) {
        return $self->p->sendError( $req, 'Failed to fetch audio', 500 );
    }

    return $self->p->sendJSONresponse( $req, { audio => $audiob64 } );
}

sub init_captcha {
    my ( $self, $req ) = @_;

    my ( $token, $image ) = $self->_fetchCaptcha;
    unless ($token) {
        $self->logger->error('CaptchEtat: failed to fetch captcha');
        return;
    }

    $self->logger->debug('CaptchEtat: captcha prepared');
    $req->token($token);
    $req->captchaHtml( $self->_get_captcha_html( $req, $image ) );

    # DEPRECATED: Compatibility with old templates
    $req->captcha($image);
}

sub _get_captcha_html {
    my ( $self, $req, $src ) = @_;

    my $sp = $self->p->staticPrefix;
    $sp =~ s/\/*$/\//;

    my $html = $self->loadTemplate(
        $req,
        'captcha',
        params => {
            STATIC_PREFIX => $sp,
            CAPTCHA_SRC   => $src,
            CAPTCHA_SIZE  => 12,
        }
    );

    # Add audio button for accessibility
    $html .= qq'<div class="form-group">
  <button type="button" id="captchetat-audio" class="btn btn-info btn-sm"
    title="Audio captcha" aria-label="Audio captcha">
    <i class="fa fa-volume-up"></i>
  </button>
</div>
<script>
(function(){
  document.getElementById("captchetat-audio").addEventListener("click", function(){
    var token = document.getElementById("token").value;
    \$.ajax({
      type: "GET",
      url: scriptname + "captcheatataudio?token=" + encodeURIComponent(token),
      dataType: "json",
      success: function(data){
        if(data.audio){
          new Audio("data:audio/wav;base64," + data.audio).play();
        }
      },
      error: function(j, status, err){
        console.error("CaptchEtat audio error", err);
      }
    });
  });
})();
</script>';

    return $html;
}

sub check_captcha {
    my ( $self, $req ) = @_;

    my $ottToken = $req->param('token');
    unless ($ottToken) {
        $self->logger->warn('CaptchEtat: no token provided');
        return 0;
    }

    my $code = $req->param('captcha');
    unless ($code) {
        $self->logger->warn('CaptchEtat: no captcha response provided');
        return 0;
    }

    # Validate input: alphanumeric, max 12 characters
    unless ( $code =~ /^[a-zA-Z0-9]{1,12}$/ ) {
        $self->logger->warn('CaptchEtat: invalid captcha input format');
        return 0;
    }

    # Retrieve UUID from OTT
    my $s = $self->ott->getToken($ottToken);
    unless ($s) {
        $self->logger->warn("CaptchEtat: token $ottToken is invalid");
        return 0;
    }

    my $uuid = $s->{captchaId};
    unless ($uuid) {
        $self->logger->error('CaptchEtat: no captchaId in token');
        return 0;
    }

    # Get OAuth token
    my $bearer = $self->_getOAuthToken;
    unless ($bearer) {
        $self->logger->error('CaptchEtat: unable to obtain OAuth token');
        return 0;
    }

    # Validate against PISTE API
    my $response = $self->ua->post(
        $self->apiUrl . '/valider-captcha',
        Content_Type  => 'application/json',
        Authorization => "Bearer $bearer",
        Content       => JSON::to_json(
            {
                uuid => $uuid,
                code => $code,
            }
        ),
    );

    unless ( $response->is_success ) {
        $self->logger->error(
            'CaptchEtat validation error: ' . $response->status_line );
        return 0;
    }

    my $result = $response->decoded_content;

    # API returns a plain boolean: "true" or "false"
    if ( $result =~ /true/i ) {
        $self->logger->debug('CaptchEtat: captcha validated');
        return 1;
    }

    $self->logger->info('CaptchEtat: captcha validation failed');
    return 0;
}

1;
