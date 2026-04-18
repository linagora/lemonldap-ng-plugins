package Lemonldap::NG::Portal::Plugins::Autoloader;

use strict;
use warnings;
use JSON qw(decode_json);
use Mouse;

extends 'Lemonldap::NG::Portal::Main::Plugin';

our $VERSION = '2.23.0';

# Default autoload directory. The placeholder is replaced at install time
# by the Makefile with the actual $(CONFDIR) path. An untouched placeholder
# (in-tree run, tests, uninstalled Perl module) falls back to the upstream
# packaging default.
our $DEFAULT_CONFDIR;
BEGIN { $DEFAULT_CONFDIR = '/etc/lemonldap-ng'; }
use constant DEFAULT_DIR => (
    ( $DEFAULT_CONFDIR =~ /^__.*__$/ )
    ? '/etc/lemonldap-ng'
    : $DEFAULT_CONFDIR
  )
  . '/autoload.d';

# Valid module-name pattern (Perl identifier with optional leading "::").
my $MODULE_RE = qr/^(?:::)?[A-Za-z_][A-Za-z0-9_:]*$/;

sub init {
    my ($self) = @_;

    my $dir = $self->conf->{autoloadDir} || DEFAULT_DIR;
    return 1 unless -d $dir;

    opendir my $dh, $dir or do {
        $self->logger->warn("Cannot open autoload dir $dir: $!");
        return 1;
    };
    my @files = sort grep { /\.json\z/ && !/^\./ } readdir $dh;
    closedir $dh;

    for my $file (@files) {
        my $path = "$dir/$file";
        my $rule = eval { _readJson($path) };
        if ( $@ or !defined $rule ) {
            $self->logger->error("Invalid autoload file $path: $@");
            next;
        }
        for my $mod ( $self->_resolve( $rule, $path ) ) {
            $self->logger->debug("Autoloading plugin $mod from $path");
            $self->p->loadPlugin($mod)
              or $self->logger->error("Autoloaded plugin $mod failed to load");
        }
    }

    return 1;
}

sub _readJson {
    my ($path) = @_;
    open my $fh, '<', $path or die "Cannot read $path: $!\n";
    local $/;
    my $raw = <$fh>;
    close $fh;
    return decode_json($raw);
}

sub _resolve {
    my ( $self, $rule, $path ) = @_;

    my @entries =
        ref $rule eq 'ARRAY' ? @$rule
      : ref $rule eq 'HASH'
      && ref $rule->{plugins} eq 'ARRAY' ? @{ $rule->{plugins} }
      : ref $rule eq 'HASH'              ? ($rule)
      :                                    ();

    my @out;
    for my $entry (@entries) {
        unless ( ref $entry eq 'HASH' and defined $entry->{module} ) {
            $self->logger->warn(
                "Autoload entry in $path lacks a 'module' field");
            next;
        }
        my $mod = $entry->{module};
        unless ( $mod =~ $MODULE_RE ) {
            $self->logger->error(
                "Autoload module name rejected: $mod (in $path)");
            next;
        }

        if ( defined( my $cond = $entry->{condition} ) ) {
            next unless $self->_evalCondition($cond);
        }
        push @out, $mod;
    }
    return @out;
}

sub _evalCondition {
    my ( $self, $cond ) = @_;
    my $conf = $self->conf;

    # "or::path/sub/key" - delegate to Portal::Main::checkConf (same syntax
    # as the static @pList of Portal::Main::Plugins).
    if ( $cond =~ /^(.*?)::(.*)$/ ) {
        return Lemonldap::NG::Portal::Main::checkConf( $conf, $2, $1 );
    }

    # Simple config key name (boolean / hashref / scalar).
    my $v = $conf->{$cond};
    return ref($v) eq 'HASH' ? scalar(%$v) : $v;
}

1;
__END__

=head1 NAME

Lemonldap::NG::Portal::Plugins::Autoloader - Filesystem-based plugin
autoloading for LemonLDAP::NG

=head1 DESCRIPTION

At initialization, this plugin scans C<autoloadDir> (default
F</etc/lemonldap-ng/autoload.d>) for JSON rule files and loads each
declared plugin through the regular
L<Lemonldap::NG::Portal::Main::Init/loadPlugin> entry point.

This lets third-party plugins installed by the plugin store (or by any
packaging system) declare themselves without the admin having to edit
C<customPlugins> in the LLNG configuration.

=head1 FILE FORMAT

One file per plugin, named C<NN-slug.json> (the C<NN> numeric prefix
controls the loading order via lexicographic sort).

  {
    "name": "MyFoo",
    "module": "::Plugins::MyFoo",
    "condition": "or::oidcRPMetaDataOptions/*/oidcRPMetaDataOptionsMyFoo"
  }

=over

=item C<module>

Mandatory. Module name, same syntax as C<customPlugins> entries.
Names starting with C<::> are resolved under C<Lemonldap::NG::Portal>.

=item C<condition>

Optional. When set, the plugin is loaded only if the condition evaluates
to true against the running LLNG configuration. Uses the same
C<< type::path/sub/key >> grammar as the static C<@pList>. Omitted means
unconditional loading.

=item C<name>

Informational only.

=back

An aggregated form is also accepted:

  { "plugins": [ { "module": "::Plugins::Foo" }, ... ] }

=cut
