package StoreTest;

# Helpers for the lemonldap-ng-store tests: a throw-away environment (ini
# file, state file, cache, autoload dir, GNUPGHOME), throw-away GPG keys,
# file:// stores with signed archives, and a runner for the CLI.

use strict;
use warnings;
use Archive::Tar;
use Cwd            qw(abs_path);
use Digest::SHA    qw(sha256_hex);
use File::Basename qw(dirname);
use File::Path     qw(make_path);
use File::Temp     qw(tempdir);
use JSON;
use Exporter 'import';

our @EXPORT =
  qw(have_gpg new_env gen_key make_store run_store read_state write_file
  gpg_import export_key);

my $ROOT   = abs_path( dirname(__FILE__) . '/../..' );    # store/
my $RUNNER = "$ROOT/t/lib/run-store.pl";
my @HOMES;

sub _bin {
    my ($name) = @_;
    for my $dir ( split /:/, $ENV{PATH} || '' ) {
        return "$dir/$name" if -x "$dir/$name";
    }
    return;
}

sub have_gpg { return _bin('gpg') ? 1 : 0 }

sub _quiet {
    my @cmd = @_;
    my $pid = fork // die "fork: $!";
    if ( $pid == 0 ) {
        open STDIN,  '<', '/dev/null';
        open STDOUT, '>', '/dev/null';
        open STDERR, '>', '/dev/null';
        { exec @cmd }
        POSIX::_exit(127);
    }
    waitpid $pid, 0;
    return $? >> 8;
}

sub write_file {
    my ( $file, $content ) = @_;
    make_path( dirname($file) );
    open my $fh, '>', $file or die "$file: $!";
    print $fh $content;
    close $fh;
}

# A fresh environment. Nothing outside the temp dir is read or written:
# GNUPGHOME points inside it too (it stands for root's default keyring).
sub new_env {
    my $dir = tempdir( CLEANUP => 1 );
    my $env = {
        dir      => $dir,
        ini      => "$dir/lemonldap-ng.ini",
        state    => "$dir/state/plugins-state.json",
        cache    => "$dir/cache",
        autoload => "$dir/autoload.d",
        gnupg    => "$dir/gnupg",
    };
    make_path( $env->{autoload}, "$dir/overrides" );
    mkdir $env->{gnupg}, 0700;
    write_file( $env->{ini}, "[store]\n" );
    push @HOMES, $env->{gnupg};
    return $env;
}

# Generate a key without passphrase in its own GnuPG home
sub gen_key {
    my ( $env, $name ) = @_;
    my $home = "$env->{dir}/keys/$name";
    make_path($home);
    chmod 0700, $home;
    push @HOMES, $home;
    my @gpg = ( 'gpg', '--homedir', $home, '--batch', '--passphrase', '' );
    my $uid = "$name <$name\@store.test>";
    _quiet( @gpg, '--quick-gen-key', $uid, 'ed25519', 'sign', 'never' ) == 0
      or _quiet( @gpg, '--quick-gen-key', $uid, 'default', 'default', 'never' )
      == 0
      or die "Cannot generate key $name";
    my $pid = open my $fh, '-|';
    die "fork: $!" unless defined $pid;

    if ( $pid == 0 ) {
        open STDERR, '>', '/dev/null';
        {
            exec 'gpg', '--homedir', $home, '--batch', '--with-colons',
              '--list-keys'
        }
        POSIX::_exit(127);
    }
    my $out = do { local $/; <$fh> };
    close $fh;
    my ($fpr) = $out =~ /^fpr:+([0-9A-F]+):/m or die "No fingerprint for $name";
    return { name => $name, home => $home, fpr => $fpr };
}

sub _sign {
    my ( $key, $file, $sig ) = @_;
    _quiet(
        'gpg',           '--homedir',
        $key->{home},    '--batch',
        '--yes',         '--passphrase',
        '',              '--pinentry-mode',
        'loopback',      '--armor',
        '--detach-sign', '--output',
        $sig,            $file
    ) == 0 or die "Cannot sign $file";
}

# Import a public key file into a GnuPG home (e.g. $env->{gnupg}, the
# "default keyring"), or into the keyring $keyring of that home (e.g.
# "trustedkeys.kbx", the default keyring of gpgv)
sub gpg_import {
    my ( $home, $file, $keyring ) = @_;
    _quiet(
        'gpg',
        '--homedir',
        $home,
        '--batch',
        '--quiet',
        (
            $keyring
            ? ( '--no-default-keyring', '--keyring', $keyring )
            : ()
        ),
        '--import',
        $file
      ) == 0
      or die "Cannot import $file";
}

# Export a public key to an armored file
sub export_key { _export(@_) }

sub _export {
    my ( $key, $dest ) = @_;
    _quiet(
        'gpg',      '--homedir', $key->{home}, '--batch',
        '--yes',    '--armor',   '--output',   $dest,
        '--export', $key->{fpr}
      ) == 0
      or die "Cannot export $key->{name}";
}

# Build a file:// store in $env->{dir}/$name.
#   key     => key whose public part the store publishes (undef: none)
#   plugins => [ { name, version, signer => key|undef, tamper => 1 } ]
# "tamper" changes the archive after signing (and fixes sha256 in the index
# accordingly), i.e. a bad signature that passes the checksum.
# Returns the store URL with a trailing slash, as the README documents it.
sub make_store {
    my ( $env, $name, %args ) = @_;
    my $dir = "$env->{dir}/$name";
    make_path($dir);
    my %store = ( name => $name );
    if ( $args{key} ) {
        _export( $args{key}, "$dir/store-key.asc" );
        $store{gpgKey} = "file://$dir/store-key.asc";
    }
    my @plugins;
    for my $p ( @{ $args{plugins} || [] } ) {
        my $archive = "llng-plugin-$p->{name}-$p->{version}.tar.gz";
        my $tar     = Archive::Tar->new;
        $tar->add_data( "$p->{name}/plugin.json",
            encode_json( { name => $p->{name}, version => $p->{version} } ) );
        $tar->add_data( "$p->{name}/autoload/$p->{name}.json",
            encode_json( { condition => 1, module => "::Plugins::Test" } ) );
        $tar->write( "$dir/$archive", COMPRESS_GZIP ) or die $tar->error;
        my %entry = (
            name    => $p->{name},
            version => $p->{version},
            archive => $archive,
        );
        if ( $p->{signer} ) {
            _sign( $p->{signer}, "$dir/$archive", "$dir/$archive.asc" );
            $entry{signature} = "$archive.asc";
        }
        if ( $p->{tamper} ) {
            $tar->add_data( "$p->{name}/autoload/$p->{name}-extra.json",
                encode_json( { condition => 1, module => '::Plugins::Evil' } )
            );
            $tar->write( "$dir/$archive", COMPRESS_GZIP ) or die $tar->error;
        }
        open my $fh, '<', "$dir/$archive" or die $!;
        binmode $fh;
        $entry{sha256} = Digest::SHA->new(256)->addfile($fh)->hexdigest;
        close $fh;
        push @plugins, \%entry;
    }
    write_file( "$dir/index.json",
        encode_json( { store => \%store, plugins => \@plugins } ) );
    return "file://$dir/";
}

# Run the CLI in a child process. Returns ($exit_code, $output) where output
# merges stdout and stderr.
sub run_store {
    my ( $env, $extra_env, @args ) = @_;
    my $out = File::Temp->new;
    my $pid = fork // die "fork: $!";
    if ( $pid == 0 ) {
        delete $ENV{$_} for grep { /^LLNG_/ } keys %ENV;
        %ENV = (
            %ENV,
            LLNG_DEFAULTCONFFILE    => $env->{ini},
            LLNG_STORE_STATEFILE    => $env->{state},
            LLNG_STORE_CACHEDIR     => $env->{cache},
            LLNG_STORE_AUTOLOADDIR  => $env->{autoload},
            LLNG_STORE_OVERRIDESDIR => "$env->{dir}/overrides",
            GNUPGHOME               => $env->{gnupg},
            %{ $extra_env || {} },
        );
        open STDIN,  '<',  '/dev/null';
        open STDOUT, '>',  $out->filename;
        open STDERR, '>&', \*STDOUT;
        { exec $^X, $RUNNER, @args }
        POSIX::_exit(127);
    }
    waitpid $pid, 0;
    my $code = $? >> 8;
    local $/;
    open my $fh, '<', $out->filename or die $!;
    my $output = <$fh> // '';
    return ( $code, $output );
}

sub read_state {
    my ($env) = @_;
    open my $fh, '<', $env->{state} or return {};
    local $/;
    return decode_json(<$fh>);
}

END {
    # Stop the gpg-agents started for the throw-away homes, without changing
    # the exit status of the test
    local $?;
    _quiet( 'gpgconf', '--homedir', $_, '--kill', 'all' )
      for grep { -d } @HOMES;
}

use POSIX ();

1;
