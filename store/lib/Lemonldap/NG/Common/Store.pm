package Lemonldap::NG::Common::Store;

use strict;
use warnings;
use Getopt::Long   qw(:config pass_through);
use File::Temp     qw(tempdir tempfile);
use File::Basename qw(dirname basename);

use Lemonldap::NG::Common::Store::Config;
use Lemonldap::NG::Common::Store::Remote;
use Lemonldap::NG::Common::Store::Verify;
use Lemonldap::NG::Common::Store::Install;
use Lemonldap::NG::Common::Store::State;

our $VERSION = '2.23.0';

# Perl modules whose Debian package name doesn't follow the lib<name>-perl
# convention. Keep in sync with debian/build-debs.sh PERL_DEB_MAP.
my %PERL_DEB_MAP = (
    'Date::Parse'    => 'libtimedate-perl',
    'Date::Format'   => 'libtimedate-perl',
    'URI::Escape'    => 'liburi-perl',
    'URI'            => 'liburi-perl',
    'HTML::Entities' => 'libhtml-parser-perl',
);

my %COMMANDS = (
    'add-store'    => \&cmd_addStore,
    'remove-store' => \&cmd_removeStore,
    'list'         => \&cmd_list,
    'info'         => \&cmd_info,
    'install'      => \&cmd_install,
    'remove'       => \&cmd_remove,
    'installed'    => \&cmd_installed,
    'update'       => \&cmd_update,
    'check'        => \&cmd_check,
    'verify'       => \&cmd_verify,
    'rebuild'      => \&cmd_rebuild,
);

sub run {
    my ( $class, @args ) = @_;

    my (
        $store_url,  $search,          $tag,      $version,
        $force,      $allow_overwrite, $activate, $help,
        $state_file, $cache_dir,       $plugins_dir
    );
    local @ARGV = @args;

    GetOptions(
        'store=s'         => \$store_url,
        'search=s'        => \$search,
        'tag=s'           => \$tag,
        'version=s'       => \$version,
        'force'           => \$force,
        'allow-overwrite' => \$allow_overwrite,
        'activate'        => \$activate,
        'state-file=s'    => \$state_file,
        'cache-dir=s'     => \$cache_dir,
        'plugins-dir=s'   => \$plugins_dir,
        'help|h'          => \$help,
    ) or _usage(1);

    my $command = shift @ARGV;
    _usage(0) if $help && !$command;
    _usage(1) unless $command;

    my $cmd_info = $COMMANDS{$command};
    unless ($cmd_info) {
        print STDERR "Unknown command: $command\n";
        _usage(1);
    }

    # Initialize components
    my $config = Lemonldap::NG::Common::Store::Config->new();

    # CLI overrides (highest priority)
    $config->override( 'stateFile',           $state_file )  if $state_file;
    $config->override( 'cacheDir',            $cache_dir )   if $cache_dir;
    $config->override( 'managerOverridesDir', $plugins_dir ) if $plugins_dir;
    $store_url = Lemonldap::NG::Common::Store::State::normUrl($store_url)
      if defined $store_url;
    my $opts = {
        config          => $config,
        store_url       => ( length( $store_url // '' ) ? $store_url : undef ),
        search          => $search,
        tag             => $tag,
        version         => $version,
        force           => $force,
        allow_overwrite => $allow_overwrite,
        activate        => $activate,
        args            => \@ARGV,
    };

    $cmd_info->($opts);
}

sub cmd_addStore {
    my ($opts) = @_;
    my $url = Lemonldap::NG::Common::Store::State::normUrl( $opts->{args}[0] );
    die "Usage: lemonldap-ng-store add-store URL\n" unless length $url;

    # Warn about HTTP
    if ( $url =~ m|^http://|i ) {
        print "WARNING: Using HTTP (not HTTPS) is insecure.\n";
        unless ( $opts->{force} ) {
            print "Use --force to add anyway.\n";
            exit 1;
        }
    }

    my $config = $opts->{config};
    if ( grep { $_ eq $url } $config->storeUrls ) {
        die "Error: Store URL already configured: $url\n";
    }
    my $mode =
      Lemonldap::NG::Common::Store::Verify->new(
        gpgVerify => $config->gpgVerify )->mode;

    # Fetch index to get GPG key URL
    my $remote = Lemonldap::NG::Common::Store::Remote->new(
        timeout  => $config->httpTimeout,
        cacheDir => $config->cacheDir,
    );
    my $keyring =
      Lemonldap::NG::Common::Store::Verify->storeKeyring( $config->cacheDir,
        $url );

    # The key is imported into a keyring dedicated to this store and its
    # fingerprint is recorded (trust on first use). Under gpgVerify=required
    # a store whose key cannot be recorded is not added: nothing could be
    # installed from it.
    my $fingerprint;
    my ( $idx_ok, $data ) = $remote->fetchIndex($url);
    my $gpg_url =
      ( $idx_ok && ref( $data->{store} ) eq 'HASH' )
      ? $data->{store}{gpgKey}
      : undef;
    if ($gpg_url) {
        print "Importing GPG key from $gpg_url...\n";
        my $tmpfile = File::Temp->new( SUFFIX => '.asc' );
        my ( $ok, $res ) =
          $remote->downloadFile( $gpg_url, $tmpfile->filename );
        if ($ok) {
            ( $ok, $res ) =
              Lemonldap::NG::Common::Store::Verify->importStoreKey(
                $tmpfile->filename, $keyring );
        }
        else {
            $res = "could not download GPG key: $res";
        }
        if ($ok) {
            $fingerprint = $res;
            print "  Imported key: $fingerprint\n";
        }
        elsif ( $mode eq 'required' ) {
            die "Error: $res\nStore not added (gpgVerify=required).\n";
        }
        else {
            print "  Warning: $res\n";
        }
    }
    else {
        my $why =
          $idx_ok
          ? 'this store does not publish a GPG key'
          : "could not fetch store index: $data";
        die "Error: $why\nStore not added (gpgVerify=required).\n"
          if $mode eq 'required';
        print "Warning: $why\n";
    }

    my ( $ok, $msg ) = $config->addStore($url);
    unless ($ok) {
        unlink $keyring if $fingerprint;
        die "Error: $msg\n";
    }
    print "$msg\n";

    # Store fingerprint associated with this store URL
    my $state =
      Lemonldap::NG::Common::Store::State->new( stateFile => $config->stateFile,
      );
    if ($fingerprint) {
        $state->addStore( $url, gpgFingerprint => $fingerprint );
        print "  GPG fingerprint saved for this store\n";
    }
    else {
        $state->removeStore($url) if $state->getStore($url);
        unlink $keyring;
    }
}

sub cmd_removeStore {
    my ($opts) = @_;
    my $url = Lemonldap::NG::Common::Store::State::normUrl( $opts->{args}[0] );
    die "Usage: lemonldap-ng-store remove-store URL\n" unless length $url;

    my ( $ok, $msg ) = $opts->{config}->removeStore($url);
    unless ($ok) {
        die "Error: $msg\n";
    }
    print "$msg\n";

    # Remove stored fingerprint and the store keyring
    my $state = Lemonldap::NG::Common::Store::State->new(
        stateFile => $opts->{config}->stateFile, );
    $state->removeStore($url);
    unlink Lemonldap::NG::Common::Store::Verify->storeKeyring(
        $opts->{config}->cacheDir, $url );
}

sub cmd_list {
    my ($opts) = @_;
    my $config = $opts->{config};

    my @stores =
      $opts->{store_url}
      ? ( $opts->{store_url} )
      : $config->storeUrls;

    unless (@stores) {
        die
"No stores configured. Use 'lemonldap-ng-store add-store URL' first.\n";
    }

    my $remote = Lemonldap::NG::Common::Store::Remote->new(
        timeout  => $config->httpTimeout,
        cacheDir => $config->cacheDir,
    );

    my $llng_version = _getLlngVersion();

    printf "%-25s %-10s %-8s %s\n", 'NAME', 'VERSION', 'COMPAT', 'SUMMARY';
    printf "%s\n", '-' x 78;

    for my $store_url (@stores) {
        my ( $ok, $data ) = $remote->fetchIndexCached($store_url);
        unless ($ok) {
            print STDERR "Warning: $data\n";
            next;
        }

        my @plugins = @{ $data->{plugins} || [] };

        # Apply search filter
        if ( $opts->{search} ) {
            my $term = lc( $opts->{search} );
            @plugins = grep {
                     $_->{name}                  =~ /\Q$term\E/i
                  || $_->{summary}               =~ /\Q$term\E/i
                  || ( $_->{description} || '' ) =~ /\Q$term\E/i
            } @plugins;
        }

        # Apply tag filter
        if ( $opts->{tag} ) {
            my $tag = lc( $opts->{tag} );
            @plugins = grep {
                my @tags = map { lc } @{ $_->{tags} || [] };
                grep { $_ eq $tag } @tags;
            } @plugins;
        }

        for my $plugin (@plugins) {
            my $compat = _checkCompat( $plugin->{llng_compat}, $llng_version );
            next if !$compat && !$opts->{force};
            my $compat_str = $compat ? 'OK' : 'INCOMPAT';
            printf "%-25s %-10s %-8s %s\n",
              $plugin->{name},
              $plugin->{version},
              $compat_str,
              $plugin->{summary} || '';
        }
    }
}

sub cmd_info {
    my ($opts) = @_;
    my $name = $opts->{args}[0]
      or die "Usage: lemonldap-ng-store info PLUGIN_NAME\n";

    my $state = Lemonldap::NG::Common::Store::State->new(
        stateFile => $opts->{config}->stateFile, );
    my ( $plugin, $err ) = _findPlugin( $opts, $name, undef, $state );
    die "$err\n" unless $plugin;

    my $llng_version = _getLlngVersion();
    my $compat       = _checkCompat( $plugin->{llng_compat}, $llng_version );

    print join(
        "\n",
        map {
            my $k = lc($_);
            my $n = $_;
            $n =~ s/_/ /g;
            my $v = $plugin->{$k} // '';
            $v = ref($v) ? join( ', ', @$v ) : $v;
            sprintf "%-14s: %s", $n, $v // ''
          } qw(Name Version Summary Description Author License LLNG_compat
          Compatible Tags Homepage Published SHA256)
    ) . "\n";
    printf "%-14s: %s\n", 'Store', $plugin->{_store_url};

    if ( $plugin->{perl_requires} && %{ $plugin->{perl_requires} } ) {
        print "Perl requires :\n";
        for my $mod ( sort keys %{ $plugin->{perl_requires} } ) {
            my $ver     = $plugin->{perl_requires}{$mod};
            my $present = _checkPerlModule( $mod, $ver );
            printf "  %-30s %-10s %s\n", $mod,
              ( $ver || 'any' ),
              ( $present ? 'installed' : 'MISSING' );
        }
    }

    # Check if locally installed
    my $installed = $state->get($name);
    printf "%-14s: %s\n", 'Installed',
      ( $installed ? "Yes (version $installed->{version})" : 'No' );
}

sub cmd_install {
    my ($opts) = @_;
    my @names = @{ $opts->{args} };
    die "Usage: lemonldap-ng-store install PLUGIN_NAME [PLUGIN_NAME...]\n"
      unless @names;

    my $config    = $opts->{config};
    my $installer = Lemonldap::NG::Common::Store::Install->new(
        managerOverridesDir => $config->managerOverridesDir,
        autoloadDir         => $config->autoloadDir,
        allowOverwrite      => $opts->{allow_overwrite},
    );
    my $state =
      Lemonldap::NG::Common::Store::State->new( stateFile => $config->stateFile,
      );

    my $errors = 0;
    for my $name (@names) {
        print "\n" if $errors || $name ne $names[0];
        eval { _installOne( $opts, $name, $config, $installer, $state ); };
        if ($@) {
            print STDERR $@;
            $errors++;
            next;
        }
    }

    # Rebuild manager once after all installs
    if ( @names > $errors ) {
        print "\nRebuilding manager files...\n";
        my ( $ok, $rebuild_msg ) = $installer->rebuildManager();
        print "  $rebuild_msg\n";
        print "\nDon't forget to restart the portal service.\n";
    }

    exit(1) if $errors;
}

sub _installOne {
    my ( $opts, $name, $config, $installer, $state ) = @_;

    # 1. Find plugin in stores (bound to the store it was installed from)
    my ( $plugin, $find_err ) =
      _findPlugin( $opts, $name, $opts->{version}, $state );
    die "Error: $find_err\n" unless $plugin;

    my $store_url = $plugin->{_store_url};

    print "Installing $plugin->{name} version $plugin->{version}"
      . " from $store_url...\n";
    my $previous = $state->get($name);
    if (   $previous
        && $previous->{installed_from}
        && $previous->{installed_from} ne $store_url )
    {
        print "  Note: switching from store $previous->{installed_from}"
          . " (--store)\n";
    }

    # 2. Check LLNG version compatibility
    my $llng_version = _getLlngVersion();
    if ( $plugin->{llng_compat}
        && !_checkCompat( $plugin->{llng_compat}, $llng_version ) )
    {
        if ( $opts->{force} ) {
            print "WARNING: Plugin requires $plugin->{llng_compat} "
              . "(current: $llng_version), installing anyway (--force)\n";
        }
        else {
            die "Error: Plugin requires LLNG $plugin->{llng_compat} "
              . "(current: $llng_version). Use --force to override.\n";
        }
    }

    # 3. Check Perl dependencies
    if ( $plugin->{perl_requires} ) {
        my @missing;
        for my $mod ( sort keys %{ $plugin->{perl_requires} } ) {
            my $ver = $plugin->{perl_requires}{$mod};
            unless ( _checkPerlModule( $mod, $ver ) ) {
                push @missing, $ver ? "$mod >= $ver" : $mod;
            }
        }
        if (@missing) {
            print "WARNING: Missing Perl dependencies:\n";
            for my $m (@missing) {
                ( my $mod = $m ) =~ s/ .*//;
                my $deb = $PERL_DEB_MAP{$mod};
                unless ($deb) {
                    ( $deb = $mod ) =~ s/::/-/g;
                    $deb = 'lib' . lc($deb) . '-perl';
                }
                print "  $m  (apt install $deb or cpan install)\n";
            }
            print
"  Plugin will be installed but may not work until dependencies are met.\n";
        }
    }

    # 4. Download archive
    # Sanitize archive/signature filenames from remote index
    my $archive_basename = basename( $plugin->{archive} || '' );
    die "Invalid archive name\n"
      unless $archive_basename =~ /^[a-zA-Z0-9._-]+\.tar\.gz$/;

    my $archive_url = "$store_url/$archive_basename";

    my $tmpdir       = tempdir( CLEANUP => 1 );
    my $archive_file = "$tmpdir/$archive_basename";

    my $remote = Lemonldap::NG::Common::Store::Remote->new(
        timeout  => $config->httpTimeout,
        cacheDir => $config->cacheDir,
    );

    print "  Downloading $plugin->{archive}...\n";
    my ( $ok, $err ) = $remote->downloadFile( $archive_url, $archive_file );
    die "Error: $err\n" unless $ok;

    # 5. Verify SHA256
    # Verifier bound to this store: its own keyring and the fingerprint
    # recorded by add-store (TOFU)
    my $verify = _storeVerifier( $config, $state, $store_url );

    print "  Verifying SHA256...\n";
    ( $ok, $err ) = $verify->verifySha256( $archive_file, $plugin->{sha256} );
    die "Error: $err\n" unless $ok;

    # 6. Verify GPG
    if ( $verify->mode ne 'disabled' ) {
        my $sig_file;
        if ( $plugin->{signature} ) {
            my $sig_basename = basename( $plugin->{signature} || '' );
            die "Invalid signature name\n"
              unless $sig_basename =~ /^[a-zA-Z0-9._-]+\.asc$/;
            my $sig_url = "$store_url/$sig_basename";
            $sig_file = "$tmpdir/$sig_basename";
            print "  Downloading GPG signature...\n";
            my ( $sig_ok, $sig_err ) =
              $remote->downloadFile( $sig_url, $sig_file );

            # The index announces a signature: it must be checked
            die "Error: could not download signature: $sig_err\n"
              unless $sig_ok;
        }

        print "  Verifying GPG signature...\n";
        ( $ok, my $gpg_msg ) = $verify->verifyGpg( $archive_file, $sig_file );
        print "  $gpg_msg\n" if $gpg_msg;
        die "Error: GPG verification failed\n" unless $ok;
    }

    # 7. Extract and validate
    print "  Extracting and validating...\n";
    my ( $ext_ok, $meta, $plugin_dir ) =
      $installer->extractAndValidate($archive_file);
    die "Error: $meta\n" unless $ext_ok;

    # 8. Check if already installed (upgrade)
    my $existing = $state->get($name);
    if ($existing) {
        print "  Upgrading from version $existing->{version}...\n";
        $installer->removeFiles( $existing->{files} );
        $state->remove($name);
    }

    # 9. Install files
    print "  Installing files...\n";
    ( $ok, my $files_or_err ) = $installer->installFiles( $plugin_dir, $meta );
    unless ($ok) {
        die "Error: $files_or_err\n";
    }

    # 10. Update state
    $state->add(
        $name,
        version        => $meta->{version},
        installed_from => $store_url,
        archive_sha256 => $plugin->{sha256},
        files          => $files_or_err,
    );

    print "  Installed " . scalar(@$files_or_err) . " file(s)\n";

    # Detect actual autoload files installed: trust the archive's
    # autoload/ directory rather than the plugin.json flag, so an
    # out-of-date metadata field never short-circuits --activate for a
    # plugin that has no rule to install.
    my $autoload_dir       = $installer->{autoloadDir};
    my @autoload_installed = $autoload_dir
      ? grep {
               defined $_
            && index( $_, "$autoload_dir/" ) == 0
            && /\.json\z/
      } @$files_or_err
      : ();

    # 11. Activate plugin if --activate was requested
    if ( $opts->{activate} ) {
        if (@autoload_installed) {
            print
"  Warning: --activate is ignored, this plugin ships an autoload rule\n";
        }
        elsif ( $meta->{customPlugins} ) {
            print "  Activating plugin...\n";
            my ( $act_ok, $act_msg ) =
              _activateCustomPlugins( $meta->{customPlugins} );
            print "  $act_msg\n";
        }
    }

    # 12. Post-install instructions
    if (@autoload_installed) {
        print
"  Plugin is autoloaded from the autoload directory, no further action needed.\n";
    }
    elsif ( $meta->{customPlugins} && !$opts->{activate} ) {
        print
"  Note: add to customPlugins in LLNG configuration: $meta->{customPlugins}\n";
    }
    if ( $meta->{post_install} ) {
        print "  Note from plugin author: $meta->{post_install}\n";
    }
}

sub cmd_remove {
    my ($opts) = @_;
    my @names = @{ $opts->{args} };
    die "Usage: lemonldap-ng-store remove PLUGIN_NAME [PLUGIN_NAME...]\n"
      unless @names;

    my $config = $opts->{config};

    my $state =
      Lemonldap::NG::Common::Store::State->new( stateFile => $config->stateFile,
      );
    my $installer = Lemonldap::NG::Common::Store::Install->new(
        managerOverridesDir => $config->managerOverridesDir,
        autoloadDir         => $config->autoloadDir,
    );

    my $errors  = 0;
    my $removed = 0;
    for my $name (@names) {
        my $installed = $state->get($name);
        unless ($installed) {
            print STDERR "Plugin not installed: $name\n";
            $errors++;
            next;
        }

        print "Removing $name (version $installed->{version})...\n";
        $installer->removeFiles( $installed->{files} );
        $state->remove($name);
        $removed++;
    }

    # Rebuild manager once after all removals
    if ($removed) {
        print "\nRebuilding manager files...\n";
        my ( $ok, $msg ) = $installer->rebuildManager();
        print "  $msg\n\nDon't forget to:
  1. Remove the plugin module(s) from customPlugins in LLNG configuration
  2. Restart the portal service\n";
    }

    exit(1) if $errors;
}

sub cmd_installed {
    my ($opts) = @_;
    my $state = Lemonldap::NG::Common::Store::State->new(
        stateFile => $opts->{config}->stateFile, );

    my %installed = $state->installed;
    unless (%installed) {
        print "No plugins installed.\n";
        return;
    }

    printf "%-25s %-10s %-20s %s\n", 'NAME', 'VERSION', 'INSTALLED', 'FROM';
    printf "%s\n", '-' x 78;

    for my $name ( sort keys %installed ) {
        my $info = $installed{$name};
        printf "%-25s %-10s %-20s %s\n",
          $name,
          $info->{version},
          $info->{installed_date} || '',
          $info->{installed_from} || '';
    }
}

sub cmd_update {
    my ($opts) = @_;
    my $config = $opts->{config};

    my @stores =
      $opts->{store_url}
      ? ( $opts->{store_url} )
      : $config->storeUrls;

    unless (@stores) {
        die "No stores configured.\n";
    }

    my $remote = Lemonldap::NG::Common::Store::Remote->new(
        timeout  => $config->httpTimeout,
        cacheDir => $config->cacheDir,
    );

    for my $store_url (@stores) {
        print "Updating index from $store_url...\n";
        my ( $ok, $data ) =
          $remote->fetchIndexCached( $store_url, 1 );    # force refresh
        if ($ok) {
            my $count = scalar @{ $data->{plugins} || [] };
            print "  $count plugin(s) available\n";
        }
        else {
            print STDERR "  Error: $data\n";
        }
    }
}

sub cmd_check {
    my ($opts) = @_;
    my $config = $opts->{config};
    my $name   = $opts->{args}[0];

    my $state =
      Lemonldap::NG::Common::Store::State->new( stateFile => $config->stateFile,
      );

    my %installed = $state->installed;
    unless (%installed) {
        print "No plugins installed.\n";
        return;
    }

    # If a specific plugin name is given, check only that one
    if ($name) {
        unless ( $installed{$name} ) {
            die "Plugin not installed: $name\n";
        }
        %installed = ( $name => $installed{$name} );
    }

    my @configured = $config->storeUrls;
    unless (@configured) {
        die "No stores configured.\n";
    }

    # --store restricts the check to the plugins of one configured store:
    # those installed from it, and those without a recorded store that it
    # publishes
    my $explicit = $opts->{store_url};
    if ( $explicit && !grep { $_ eq $explicit } @configured ) {
        die "Not a configured store: $explicit\n";
    }
    my @stores = $explicit ? ($explicit) : @configured;

    # Compare each plugin with the store it was installed from only: another
    # store publishing the same name at a higher version is not an update
    my ( $found,   $errors ) = _candidates( $config, \@stores );
    my ( $updates, @notes )  = (0);
    for my $pname ( sort keys %installed ) {
        my $local      = $installed{$pname};
        my $from       = $local->{installed_from};
        my @publishers = sort grep { $found->{$_}{$pname} } keys %$found;
        my $store;
        if ( $from && $explicit && $from ne $explicit ) {
            push @notes, "$pname: installed from $from, not checked"
              if $name;
            next;
        }
        if ($from) {
            unless ( grep { $_ eq $from } @configured ) {
                push @notes,
                  "$pname: installed from $from, which is no longer configured";
                next;
            }
            $store = $from;
        }
        elsif ( @publishers == 1 ) {
            $store = $publishers[0];
        }
        elsif (@publishers) {
            push @notes,
                "$pname: published by several stores ("
              . join( ', ', @publishers )
              . '), use install --store=URL';
            next;
        }
        else {
            push @notes,
              "$pname: not found in the stores that could be fetched"
              . _fetchErrors( $errors, @stores )
              if %$errors;
            next;
        }
        if ( my $err = $errors->{$store} ) {
            push @notes, "$pname: cannot fetch the index of $store: $err";
            next;
        }
        my $candidate = _best( $found->{$store}{$pname} ) or next;
        if ( _versionCmp( $candidate->{version}, $local->{version} ) > 0 ) {
            printf "%-25s %s -> %s\n", $pname, $local->{version},
              $candidate->{version};
            $updates++;
        }
    }

    if ( $updates == 0 ) {
        print "All installed plugins"
          . ( $explicit ? " from $explicit" : '' )
          . " are up to date.\n";
    }
    else {
        print "\n$updates update(s) available.\n";
    }
    print "\nNote: $_\n" for @notes;
}

sub cmd_verify {
    my ($opts) = @_;
    my $file = $opts->{args}[0]
      or die "Usage: lemonldap-ng-store verify ARCHIVE_FILE [--store=URL]\n";

    unless ( -r $file ) {
        die "Cannot read file: $file\n";
    }

    my $config = $opts->{config};

    # Extract and validate structure
    my $installer = Lemonldap::NG::Common::Store::Install->new(
        managerOverridesDir => $config->managerOverridesDir,
        autoloadDir         => $config->autoloadDir,
    );

    print "Validating archive structure...\n";
    my ( $ok, $meta, $plugin_dir ) = $installer->extractAndValidate($file);
    if ($ok) {
        print "  Structure: OK
  Name:      $meta->{name}
  Version:   $meta->{version}\n";
    }
    else {
        print "  Structure: FAILED - $meta\n";
        exit 1;
    }

    # GPG verification of the .asc file alongside, against the key of the
    # store given by --store, or of any configured store
    my $mode =
      Lemonldap::NG::Common::Store::Verify->new(
        gpgVerify => $config->gpgVerify )->mode;
    my $sig_file = "${file}.asc";
    my $gpg_ok   = 1;
    if ( $mode eq 'disabled' ) {
        print "  GPG:       verification disabled\n";
    }
    elsif ( !-r $sig_file ) {
        if ( $mode eq 'required' ) {
            print "  GPG:       FAILED - no .asc signature file found\n";
            $gpg_ok = 0;
        }
        else {
            print "  GPG:       Warning: no .asc signature file found"
              . " (gpgVerify=optional)\n";
        }
    }
    else {
        my $state = Lemonldap::NG::Common::Store::State->new(
            stateFile => $config->stateFile, );
        my @stores =
          $opts->{store_url} ? ( $opts->{store_url} ) : $config->storeUrls;
        my ( $verified, @fail, @warn );
        for my $url (@stores) {
            my ( $v_ok, $msg, $fpr ) =
              _storeVerifier( $config, $state, $url )
              ->verifyGpg( $file, $sig_file );
            if ( $v_ok && $fpr ) {
                $verified = "$msg, store $url";
                last;
            }
            push @{ $v_ok ? \@warn : \@fail }, "$url: $msg";
        }
        if ($verified) {
            print "  GPG:       $verified\n";
        }
        elsif ( @fail || $mode eq 'required' ) {
            print "  GPG:       FAILED\n";
            print "    $_\n" for @fail;
            print "    no store configured to check the signature against\n"
              unless @stores;
            $gpg_ok = 0;
        }
        else {
            print "  GPG:       Warning: signature not checked\n";
            print "    $_\n" for @warn;
        }
    }

    unless ($gpg_ok) {
        print "Archive NOT valid.\n";
        exit 1;
    }
    print "Archive valid.\n";
}

sub cmd_rebuild {
    my ($opts) = @_;
    my $config = $opts->{config};

    my $installer = Lemonldap::NG::Common::Store::Install->new(
        managerOverridesDir => $config->managerOverridesDir,
        autoloadDir         => $config->autoloadDir,
    );

    print "Rebuilding manager files...\n";
    my ( $ok, $msg ) = $installer->rebuildManager();
    print "  $msg\n";
    unless ($ok) {
        die "Error: rebuild failed\n";
    }
}

#
# Helper functions
#

# Plugin entries published by each store: { store_url => { name => [entries] } }
# Restricted to $name when given. Also returns the stores whose index could
# not be fetched: { store_url => error }, so that a network failure is not
# reported as "the store does not publish it".
# Returns ($found, $errors)
sub _candidates {
    my ( $config, $stores, $name ) = @_;
    my $remote = Lemonldap::NG::Common::Store::Remote->new(
        timeout  => $config->httpTimeout,
        cacheDir => $config->cacheDir,
    );
    my ( %found, %errors );
    for my $store_url (@$stores) {
        my ( $ok, $data ) = $remote->fetchIndexCached($store_url);
        unless ($ok) {
            $errors{$store_url} = $data // 'unknown error';
            next;
        }
        unless ( ref($data) eq 'HASH' ) {
            $errors{$store_url} = 'invalid store index';
            next;
        }
        for my $p ( @{ $data->{plugins} || [] } ) {
            next unless ref($p) eq 'HASH' && defined $p->{name};
            next if defined $name && $p->{name} ne $name;
            push @{ $found{$store_url}{ $p->{name} } },
              { %$p, _store_url => $store_url };
        }
    }
    return ( \%found, \%errors );
}

# " (could not fetch the index of URL: error; ...)" for the given stores
sub _fetchErrors {
    my ( $errors, @stores ) = @_;
    my @msg = map { "$_: $errors->{$_}" } grep { $errors->{$_} } @stores;
    return @msg
      ? ' (could not fetch the index of ' . join( '; ', @msg ) . ')'
      : '';
}

# Highest version among entries, or the entry with the wanted version
sub _best {
    my ( $entries, $wanted_version ) = @_;
    my $best;
    for my $p ( @{ $entries || [] } ) {
        next if $wanted_version && ( $p->{version} // '' ) ne $wanted_version;
        $best = $p
          if !$best || _versionCmp( $p->{version}, $best->{version} ) > 0;
    }
    return $best;
}

# Resolve the store a plugin is taken from. A plugin is bound to the store it
# was installed from (installed_from), and a name published by several stores
# is not installed without --store, so that a store cannot shadow a plugin of
# another one by publishing the same name at a higher version.
# Returns ($plugin) or (undef, $error)
sub _findPlugin {
    my ( $opts, $name, $wanted_version, $state ) = @_;
    my $config     = $opts->{config};
    my @configured = $config->storeUrls;
    my $explicit   = $opts->{store_url};

    my @stores = $explicit ? ($explicit) : @configured;
    my ( $found, $errors ) = _candidates( $config, \@stores, $name );
    my @publishers = sort grep { $found->{$_}{$name} } keys %$found;
    return ( undef,
        "Plugin not found: $name" . _fetchErrors( $errors, @stores ) )
      unless @publishers;

    my $installed = $state ? $state->get($name) : undef;
    my $bound     = $installed && $installed->{installed_from};
    my $from;
    if ($explicit) {
        $from = $explicit;
    }
    elsif ($bound) {
        unless ( grep { $_ eq $bound } @configured ) {
            return ( undef,
                    "$name was installed from $bound, which is no longer a "
                  . "configured store. Use --store=URL to install it from "
                  . "another store." );
        }
        if ( my $err = $errors->{$bound} ) {
            return ( undef,
                    "$name was installed from $bound, whose index could not "
                  . "be fetched: $err" );
        }
        unless ( $found->{$bound}{$name} ) {
            return ( undef,
                    "$name was installed from $bound, which does not publish "
                  . "it (published by: "
                  . join( ', ', @publishers )
                  . "). Use --store=URL to switch stores." );
        }
        $from = $bound;
    }
    elsif ( @publishers > 1 ) {
        return ( undef,
                "$name is published by several stores ("
              . join( ', ', @publishers )
              . "). Use --store=URL to choose one." );
    }
    else {
        $from = $publishers[0];
    }

    my $best = _best( $found->{$from}{$name}, $wanted_version );
    return ( undef,
            "Plugin not found: $name"
          . ( $wanted_version ? " version $wanted_version" : '' )
          . " in $from"
          . _fetchErrors( $errors, $from ) )
      unless $best;
    return ($best);
}

# Verifier bound to one store: its keyring and its recorded fingerprint.
# A store added by a client without per-store keyrings has its key in the
# GnuPG keyring of the user who ran add-store: it is moved, by fingerprint,
# into the store keyring the first time it is needed.
sub _storeVerifier {
    my ( $config, $state, $store_url ) = @_;
    my $info = $state->getStore($store_url);
    my $fpr  = $info && $info->{gpgFingerprint};
    my $keyring =
      Lemonldap::NG::Common::Store::Verify->storeKeyring( $config->cacheDir,
        $store_url );
    my $verify = Lemonldap::NG::Common::Store::Verify->new(
        gpgVerify       => $config->gpgVerify,
        gpgKeyring      => $keyring,
        gpgFingerprints => [ $fpr || () ],
    );
    if ( $fpr && !-s $keyring && $verify->mode ne 'disabled' ) {
        my $tmp = File::Temp->new( SUFFIX => '.gpg' );
        my ( $ok, $err ) =
          Lemonldap::NG::Common::Store::Verify->exportFromDefaultKeyring( $fpr,
            $tmp->filename, $config->gpgKeyring );
        ( $ok, $err ) =
          Lemonldap::NG::Common::Store::Verify->importStoreKey( $tmp->filename,
            $keyring, $fpr )
          if $ok;
        if ($ok) {
            print "  Key $fpr of $store_url moved to its own keyring\n";
        }
        else {
            print STDERR "  Warning: no keyring for $store_url and key $fpr"
              . " not found in the GnuPG keyring: $err\n";
        }
    }
    return $verify;
}

sub _getLlngVersion {
    eval { require Lemonldap::NG::Common };
    return $Lemonldap::NG::Common::VERSION || '0';
}

# Simple version comparison (X.Y.Z format)
sub _versionCmp {
    my ( $a, $b ) = @_;
    my @a = split /\./, ( $a || '0' );
    my @b = split /\./, ( $b || '0' );
    for my $i ( 0 .. 3 ) {
        my $cmp = ( $a[$i] || 0 ) <=> ( $b[$i] || 0 );
        return $cmp if $cmp;
    }
    return 0;
}

# Check version compatibility string like ">=2.20.0" or ">=2.20.0,<3.0.0"
sub _checkCompat {
    my ( $compat_str, $current ) = @_;
    return 1 unless $compat_str;
    return 1 unless $current;

    for my $constraint ( split /\s*,\s*/, $compat_str ) {
        if ( $constraint =~ /^>=\s*(.+)/ ) {
            return 0 if _versionCmp( $current, $1 ) < 0;
        }
        elsif ( $constraint =~ /^>\s*(.+)/ ) {
            return 0 if _versionCmp( $current, $1 ) <= 0;
        }
        elsif ( $constraint =~ /^<=\s*(.+)/ ) {
            return 0 if _versionCmp( $current, $1 ) > 0;
        }
        elsif ( $constraint =~ /^<\s*(.+)/ ) {
            return 0 if _versionCmp( $current, $1 ) >= 0;
        }
        elsif ( $constraint =~ /^==?\s*(.+)/ ) {
            return 0 if _versionCmp( $current, $1 ) != 0;
        }
    }
    return 1;
}

sub _activateCustomPlugins {
    my ($modules) = @_;

    # Find lemonldap-ng-cli
    my $cli;
    for my $dir ( split /:/, $ENV{PATH} || '' ) {
        my $path = "$dir/lemonldap-ng-cli";
        if ( -x $path ) { $cli = $path; last }
    }
    unless ($cli) {
        return ( 0,
            'lemonldap-ng-cli not found, cannot activate automatically' );
    }

    # Read current customPlugins value
    my $current = _capture( $cli, '--json', '1', 'get', 'customPlugins' );
    chomp $current;

    # Parse: cli outputs JSON, could be "value" or null
    $current =~ s/^"(.*)"$/$1/s;
    $current = '' if $current eq 'null' || $current eq '""';

    # Build new value: add each module if not already present
    my @existing = $current ? split( /\s*,\s*/, $current ) : ();
    my @to_add   = split /\s*,\s*/, $modules;
    my $changed  = 0;

    for my $mod (@to_add) {
        $mod =~ s/^\s+|\s+$//g;
        unless ( $mod =~ /^(?:::\w+(?:::\w+)*|Lemonldap::NG::\w+(?:::\w+)*)$/ )
        {
            return ( 0, "Invalid module name in customPlugins: $mod" );
        }
        unless ( grep { $_ eq $mod } @existing ) {
            push @existing, $mod;
            $changed = 1;
        }
    }

    unless ($changed) {
        return ( 1, 'Plugin already in customPlugins' );
    }

    my $new_value = join( ', ', @existing );
    my $output =
      _capture( $cli, '--yes', '1', 'set', 'customPlugins', $new_value );
    my $exit = $? >> 8;

    if ( $exit != 0 ) {
        return ( 0, "Failed to update customPlugins: $output" );
    }

    return ( 1, "Activated in customPlugins: $new_value" );
}

sub _checkPerlModule {
    my ( $module, $min_version ) = @_;
    return 0 unless $module =~ /^\w+(?:::\w+)*$/;
    eval "require $module";    ## no critic (BuiltinFunctions::ProhibitStringyEval)
    return 0 if $@;
    if ( $min_version && $min_version ne '0' ) {
        eval { $module->VERSION($min_version) };
        return 0 if $@;
    }
    return 1;
}

# Safe capture of command output (avoids shell interpolation)
sub _capture {
    my @cmd = @_;
    open my $fh, '-|', @cmd or return '';
    local $/;
    my $output = <$fh>;
    close $fh;
    return $output // '';
}

sub _usage {
    my ($exitcode) = @_;
    print <<'USAGE';
Usage: lemonldap-ng-store COMMAND [OPTIONS]

Commands:
  add-store URL            Add an approved store URL
  remove-store URL         Remove a store URL
  list                     List available plugins
  info PLUGIN              Show plugin details
  install PLUGIN           Install a plugin
  remove PLUGIN            Remove an installed plugin
  installed                List installed plugins
  update                   Refresh store indexes
  check [PLUGIN]           Check for updates (--store: of that store's
                           plugins only)
  verify ARCHIVE           Verify a local archive (exit 1 if it fails)
  rebuild                  Rebuild manager files (after LLNG upgrade)

Options:
  --store=URL              Use a specific store URL (install: required when
                           several stores publish the plugin, or to move an
                           installed plugin to another store; check: only the
                           plugins installed from that store)
  --search=TERM            Filter plugins by search term
  --tag=TAG                Filter plugins by tag
  --version=X.Y.Z          Install a specific version
  --force                  Skip compatibility checks
  --allow-overwrite        Allow overwriting existing files (e.g. core plugins)
  --activate               Add plugin to customPlugins (requires lemonldap-ng-cli)
  --state-file=PATH        Override state file path
  --cache-dir=PATH         Override cache directory
  --plugins-dir=PATH       Override manager plugins directory
  --help, -h               Show this help

Environment variables (override lemonldap-ng.ini):
  LLNG_DEFAULTCONFFILE     Path to lemonldap-ng.ini
  LLNG_STORE_URLS          Store URLs (comma-separated)
  LLNG_STORE_STATEFILE     State file path
  LLNG_STORE_CACHEDIR      Cache directory
  LLNG_STORE_OVERRIDESDIR  Manager overrides directory
  LLNG_STORE_GPGVERIFY     GPG verification mode (required/optional/disabled,
                           default: required)
  LLNG_STORE_GPGKEYRING    Legacy keyring, only read to migrate a store added
                           before per-store keyrings
USAGE
    exit $exitcode;
}

1;
