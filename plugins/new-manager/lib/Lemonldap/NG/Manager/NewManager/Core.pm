package Lemonldap::NG::Manager::NewManager::Core;

# Subclass of Lemonldap::NG::Manager the manager object is reblessed into by
# Lemonldap::NG::Manager::NewManager: it adds the interface switch of
# LLNG >= 3.0 (Manager.pm betaUi / sendHtml / javascript).

use strict;
use parent -norequire, 'Lemonldap::NG::Manager';

our $VERSION = '0.5.3';

# Name of the cookie used to opt-in the new (beta) manager interface
use constant BETAUICOOKIE => 'llngmanagerbeta';

sub wrap {
    my ( $class, $p, $conf ) = @_;
    return if $p->isa($class);
    unless ( ref($p) eq 'Lemonldap::NG::Manager' ) {
        $p->logger->error( 'newManager: unexpected manager class ' . ref($p) );
        return;
    }

    # The new interface stylesheets are real files (covered by 'self'), but
    # MUI/Emotion also inserts <style> elements at runtime: 'unsafe-inline'
    # on style-src allows them while inline "style=" attributes stay
    # forbidden. img-src also trusts the portal, which serves the
    # application logos shown in the menu editor.
    my $portal = $conf->{portal} // '';
    $portal =~ s#https?://([^/]*).*#$1#;
    $p->{_newManagerCsp} =
        "default-src 'self' $portal;"
      . "style-src 'self' 'unsafe-inline';style-src-attr 'none';"
      . "img-src 'self' data: $portal;font-src 'self' data:;"
      . "frame-ancestors 'none';form-action 'self';";
    bless $p, $class;
    return 1;
}

## @method boolean betaUi($req)
# Return true if the user opted in the new interface. The cookie value is
# only tested against "1": it must never be used to build a path.
sub betaUi {
    my ( $self, $req ) = @_;
    my $c = $req->cookies->{ +BETAUICOOKIE };
    return ( defined $c and $c eq '1' ) ? 1 : 0;
}

sub sendHtml {
    my ( $self, $req, $template, %args ) = @_;
    my $new = 0;

    if ( !$args{templateDir} and $self->betaUi($req) ) {

        # "/" (default route) opens the home page of the new interface
        $template = 'home' if ( $req->path_info // '' ) =~ m#^/?$#;

        my @dirs =
          ref $self->templateDir eq 'ARRAY'
          ? @{ $self->templateDir }
          : ( $self->templateDir );
        s#/+$## for @dirs;

        # Pages without a new template (viewer, api...) keep the historical
        # one and its CSP
        if ( grep { -e "$_/new/$template.tpl" } @dirs ) {
            $new = 1;
            $args{templateDir} = [ ( map { "$_/new" } @dirs ), @dirs ];
        }
    }
    my $res = $self->SUPER::sendHtml( $req, $template, %args );
    if ($new) {
        my $h = $res->[1];
        for ( my $i = 0 ; $i < @$h ; $i += 2 ) {
            $h->[ $i + 1 ] = $self->{_newManagerCsp}
              if lc( $h->[$i] ) eq 'content-security-policy';
        }
    }
    return $res;
}

# The new interface displays the LLNG version
sub javascript {
    my $self = shift;
    return $self->SUPER::javascript(@_)
      . "var version='$Lemonldap::NG::Manager::VERSION';";
}

1;
