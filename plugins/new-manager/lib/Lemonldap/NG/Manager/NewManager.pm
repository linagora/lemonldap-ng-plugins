package Lemonldap::NG::Manager::NewManager;

# Backport of the new (React) manager interface to LemonLDAP::NG 2.23.x.
#
# Enable it by appending "newManager" to enabledModules (lemonldap-ng.ini,
# [manager] section). It must NOT be the first module: the first one gives
# the default route.
#
# Like in LLNG >= 3.0, the "llngmanagerbeta" cookie selects the interface:
# when set to "1", templates are searched in templates/new/ first and the
# pages are served with a CSP allowing the MUI runtime styles. The tab this
# module adds to the historical interface sets this cookie; the new interface
# has a "Back to the classic manager" link that drops it.

use strict;
use Mouse;
use Lemonldap::NG::Manager::NewManager::Core;

our $VERSION = '0.5.3';

extends 'Lemonldap::NG::Manager::Plugin';

# Tab of the historical interface: opt in the new one
use constant defaultRoute => 'newmanager.html';
use constant icon         => 'star';

sub init {
    my ( $self, $conf ) = @_;
    my $p = $self->p;

    # Methods of the manager object itself have to be overridden (sendHtml is
    # called by every module): rebless it into a subclass of its own class
    Lemonldap::NG::Manager::NewManager::Core->wrap( $p, $conf );

    $self->addRoute( 'newmanager.html' => 'optIn', ['GET'] )
      ->addRoute( 'home.html' => 'home', ['GET'] );
    return 1;
}

# Set the cookie and open the new interface
sub optIn {
    my ( $self, $req ) = @_;
    return [
        302,
        [
            Location     => './',
            'Set-Cookie' => Lemonldap::NG::Manager::NewManager::Core::BETAUICOOKIE
              . '=1; path=/; SameSite=Lax',
        ],
        []
    ];
}

# Home page of the new interface, also served on "/" (see Core::sendHtml).
# The historical interface has none.
sub home {
    my ( $self, $req ) = @_;
    return $self->p->betaUi($req)
      ? $self->p->sendHtml( $req, 'home' )
      : [ 302, [ Location => './' ], [] ];
}

1;
