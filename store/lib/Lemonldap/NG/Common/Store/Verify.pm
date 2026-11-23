package Lemonldap::NG::Common::Store::Verify;

use strict;
use warnings;
use Digest::SHA    qw(sha256_hex);
use File::Basename qw(dirname);
use File::Path     qw(make_path);
use File::Temp;
use POSIX ();
use Lemonldap::NG::Common::Store::State;

our $VERSION = '2.23.0';

# gpgVerify modes:
#   required (default): every archive must carry a signature made by the key
#       recorded for its store at add-store time.
#   optional: an archive the store publishes without a signature, or a store
#       without a recorded key, is accepted with a warning. A signature that
#       is checked is checked as in "required": a bad signature or a signer
#       other than the store key is always fatal.
#   disabled: no GPG check at all.
# Any other value is treated as "required".
my %MODES = map { $_ => 1 } qw(required optional disabled);

sub new {
    my ( $class, %args ) = @_;
    my $mode = lc( $args{gpgVerify} // 'required' );
    $mode =~ s/^\s+|\s+$//g;
    $mode = 'required' unless $MODES{$mode};
    my $self = bless {
        gpgVerify       => $mode,
        gpgKeyring      => $args{gpgKeyring},
        gpgFingerprints => [
            map  { _normFpr($_) }
            grep { defined && length } @{ $args{gpgFingerprints} || [] }
        ],
    }, $class;
    return $self;
}

sub mode { return $_[0]->{gpgVerify} }

# Verify SHA256 checksum of a file
# Returns (success, error_message)
sub verifySha256 {
    my ( $self, $file, $expected ) = @_;

    open my $fh, '<', $file
      or return ( 0, "Cannot read file $file: $!" );
    binmode $fh;
    my $sha = Digest::SHA->new(256);
    $sha->addfile($fh);
    close $fh;

    my $actual = $sha->hexdigest;
    if ( lc($actual) ne lc( $expected // '' ) ) {
        return ( 0,
                "SHA256 mismatch:\n"
              . "  expected: "
              . ( $expected // '(none)' ) . "\n"
              . "  got:      $actual" );
    }

    return ( 1, undef );
}

# Verify a GPG detached signature against the keyring of one store
# Returns (success, message, verified_fingerprint); the fingerprint is only
# set when the signature was actually checked
#
# The signature is checked with gpgv (or gpg with an empty home and
# --no-default-keyring) on the store's own keyring only, and the primary key
# fingerprint read from the machine-readable VALIDSIG status line must equal
# the fingerprint recorded for the store. Only a missing signature, a missing
# gpg or a store without a recorded key are tolerated, and only in "optional"
# mode: a signature that fails, or that another key made, is always refused.
sub verifyGpg {
    my ( $self, $archive_file, $sig_file ) = @_;
    my $mode = $self->{gpgVerify};

    # If GPG verification is disabled, skip
    if ( $mode eq 'disabled' ) {
        return ( 1, 'GPG verification disabled' );
    }

    # Check if signature file exists
    unless ( $sig_file && -r $sig_file ) {
        return ( 0, 'GPG signature required but not available' )
          if $mode eq 'required';
        return ( 1,
            'Warning: no GPG signature available (gpgVerify=optional)' );
    }

    # The store must have a recorded key and its own keyring
    my @fprs    = @{ $self->{gpgFingerprints} };
    my $keyring = $self->{gpgKeyring};
    unless ( @fprs && $keyring && -s $keyring ) {
        my $why =
          @fprs
          ? 'the keyring of this store is missing'
          : 'no GPG key is recorded for this store';
        return ( 0,
                "GPG verification required but $why. Run "
              . "'remove-store URL' then 'add-store URL' to record it." )
          if $mode eq 'required';
        return ( 1,
            "Warning: signature not checked, $why (gpgVerify=optional)" );
    }

    # Check if gpgv or gpg is available
    my ( @cmd, $home );
    if ( my $gpgv = _findBin('gpgv') ) {
        @cmd = ( $gpgv, '--keyring', $keyring, '--status-fd', '1' );
    }
    elsif ( my $gpg = _findGpg() ) {

        # Empty home: no default keyring, no gpg.conf, no key retrieval
        $home = File::Temp->newdir();
        @cmd  = (
            $gpg,             '--homedir',
            $home->dirname,   '--batch',
            '--no-autostart', '--no-default-keyring',
            '--keyring',      $keyring,
            '--trust-model',  'always',
            '--status-fd',    '1',
            '--verify'
        );
    }
    else {
        return ( 0,
            'gpg not found but GPG verification is required. Install gnupg.' )
          if $mode eq 'required';
        return ( 1,
            'Warning: gpg not found, signature not checked (gpgVerify=optional)'
        );
    }
    push @cmd, $sig_file, $archive_file;

    my ( $exit, $status, $errors ) = _run(@cmd);
    return ( 0, "Cannot run $cmd[0]: $errors" ) unless defined $exit;

    # Read the status lines only: unlike the human-readable output, they do
    # not echo the user IDs chosen by the key owner
    my ( @valid, $bad );
    for my $line ( split /\n/, $status ) {
        next unless $line =~ s/^\[GNUPG:\] //;
        my ( $kw, @f ) = split / /, $line;
        if ( $kw eq 'VALIDSIG' ) {

            # VALIDSIG <fpr> <date> <ts> <expire> <ver> <rsvd> <pkalgo>
            #          <hashalgo> <class> [<primary-key-fpr>]
            push @valid, _normFpr( defined $f[9] ? $f[9] : $f[0] );
        }
        elsif (
            $kw =~ /^(?:BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|NO_PUBKEY)$/ )
        {
            $bad = 1;
        }
    }

    if ( $exit != 0 || $bad || !@valid ) {
        $errors =~ s/\s+$//;
        return ( 0, "GPG verification failed:\n$errors" );
    }

    my %trusted = map { $_ => 1 } @fprs;
    for my $fp (@valid) {
        return ( 0,
                "GPG signature made by $fp, which is not the key "
              . "recorded for this store (@fprs)" )
          unless $trusted{$fp};
    }

    return ( 1, "GPG signature verified (key $valid[0])", $valid[0] );
}

# Import the public key published by a store into a keyring that holds this
# key only. The key is loaded in a throw-away GnuPG home, so neither the
# caller's default keyring nor its gpg.conf is involved, then exported to
# $keyring.
# If $expected is given, the file must contain that key; otherwise it must
# contain exactly one primary key.
# Returns (success, fingerprint_or_error)
sub importStoreKey {
    my ( $class, $key_file, $keyring, $expected ) = @_;
    my $gpg = _findGpg() or return ( 0, 'gpg not found. Install gnupg.' );
    $expected = _normFpr($expected) if defined $expected;

    my $home = File::Temp->newdir();
    my @base = (
        $gpg, '--homedir', $home->dirname, '--batch', '--no-autostart',
        '--no-tty'
    );

    my ( $exit, undef, $err ) = _run( @base, '--import', $key_file );
    return ( 0, "GPG import failed: $err" )
      unless defined $exit && $exit == 0;

    ( $exit, my $out, $err ) = _run( @base, '--with-colons', '--list-keys' );
    return ( 0, "Cannot list imported keys: $err" )
      unless defined $exit && $exit == 0;

    # Primary fingerprints: the "fpr" record that follows each "pub" record
    my ( @primary, $in_pub );
    for my $line ( split /\n/, $out ) {
        my @f = split /:/, $line;
        next unless @f;
        if    ( $f[0] eq 'pub' ) { $in_pub = 1 }
        elsif ( $f[0] eq 'sub' ) { $in_pub = 0 }
        elsif ( $f[0] eq 'fpr' && $in_pub ) {
            push @primary, _normFpr( $f[9] );
            $in_pub = 0;
        }
    }

    my $fpr;
    if ( defined $expected ) {
        ($fpr) = grep { $_ eq $expected } @primary;
        return ( 0, "Key $expected not found in $key_file" ) unless $fpr;
    }
    elsif ( @primary == 1 ) {
        $fpr = $primary[0];
    }
    else {
        return ( 0,
            'The store key file must contain exactly one key, found '
              . scalar(@primary) );
    }

    my $dir = dirname($keyring);
    unless ( -d $dir ) {
        eval { make_path( $dir, { mode => 0755 } ) };
        return ( 0, "Cannot create $dir: $@" ) if $@ || !-d $dir;
    }
    my $tmp = "$keyring.tmp$$";
    unlink $tmp;
    ( $exit, undef, $err ) = _run( @base, '--output', $tmp, '--export', $fpr );
    unless ( defined $exit && $exit == 0 && -s $tmp ) {
        unlink $tmp;
        return ( 0, "GPG export failed: $err" );
    }
    chmod 0644, $tmp;
    unless ( rename $tmp, $keyring ) {
        my $e = $!;
        unlink $tmp;
        return ( 0, "Cannot write $keyring: $e" );
    }
    return ( 1, $fpr );
}

# Export the key $fpr from the caller's default GnuPG keyring (plus the
# legacy gpgKeyring, if any), where clients without per-store keyrings
# imported store keys, to $dest. Used once to migrate a store added by such
# a client; the result still goes through importStoreKey with the recorded
# fingerprint.
# Returns (success, error)
sub exportFromDefaultKeyring {
    my ( $class, $fpr, $dest, $extra_keyring ) = @_;
    my $gpg = _findGpg() or return ( 0, 'gpg not found' );
    my ( $exit, undef, $err ) = _run(
        $gpg,
        '--batch',
        '--no-autostart',
        '--no-tty',
        (
            $extra_keyring && -r $extra_keyring
            ? ( '--keyring', $extra_keyring )
            : ()
        ),
        '--output',
        $dest, '--yes',
        '--export',
        _normFpr($fpr)
    );
    return ( 0, $err || 'key not found' )
      unless defined $exit && $exit == 0 && -s $dest;
    return ( 1, undef );
}

# Path of the keyring that holds the key of one store
sub storeKeyring {
    my ( $class, $cacheDir, $url ) = @_;
    return
      "$cacheDir/keyrings/"
      . Lemonldap::NG::Common::Store::State::urlFileKey($url) . '.gpg';
}

# Check HTTPS transport security
# Returns (secure, warning_message)
sub checkTransport {
    my ( $self, $url ) = @_;
    if ( $url =~ m|^https://|i ) {
        return ( 1, undef );
    }
    if ( $url =~ m|^http://|i ) {
        return ( 0, "WARNING: Store URL uses HTTP (not HTTPS): $url" );
    }
    return ( 0, "Unknown protocol in URL: $url" );
}

sub _findGpg { return _findBin('gpg') }

sub _findBin {
    my ($name) = @_;
    for my $dir ( '/usr/bin', '/usr/local/bin', split /:/, $ENV{PATH} || '' ) {
        my $path = "$dir/$name";
        return $path if -x $path;
    }
    return undef;
}

sub _normFpr {
    my ($fpr) = @_;
    $fpr //= '';
    $fpr =~ s/\s+//g;
    $fpr =~ s/^0x//i;
    return uc $fpr;
}

# Run a command without a shell. Returns (exit_code, stdout, stderr), or
# (undef, '', error) if it could not be started.
sub _run {
    my @cmd   = @_;
    my $errfh = File::Temp->new();
    my $pid   = open my $fh, '-|';
    return ( undef, '', "Cannot fork: $!" ) unless defined $pid;
    if ( $pid == 0 ) {
        open STDIN,  '<', '/dev/null';
        open STDERR, '>', $errfh->filename;
        { exec { $cmd[0] } @cmd }
        print STDERR "Cannot exec $cmd[0]: $!\n";
        POSIX::_exit(127);    # no destructors: temp files belong to parent
    }
    local $/;
    my $out = <$fh> // '';
    close $fh;
    my $status = $?;
    seek $errfh, 0, 0;
    my $err = <$errfh> // '';

    # A command killed by a signal has no exit code ($? >> 8 is 0): report
    # it as a failure, with the shell convention 128 + signal
    if ( my $sig = $status & 127 ) {
        $err .= "$cmd[0] killed by signal $sig\n";
        return ( 128 + $sig, $out, $err );
    }
    return ( $status >> 8, $out, $err );
}

1;
