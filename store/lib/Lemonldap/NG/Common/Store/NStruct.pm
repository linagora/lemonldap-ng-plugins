package Lemonldap::NG::Common::Store::NStruct;

# Build nstruct.json, the configuration tree of the new (React) manager, on
# LLNG versions whose Lemonldap::NG::Manager::Build predates the
# "newStructFile" option (< 3.0).
#
# nstruct.json is struct.json in which each top-level "cnodes" reference
# (e.g. "virtualHosts") is replaced by the scanned tree of the matching
# ctree (e.g. "virtualHost"), exactly like LLNG >= 3.0 Build.pm does.
#
# It must run in the llng-build-manager-files process, after Build->run():
# the ctrees are then the ones merged with the plugin extensions.

use strict;
use warnings;
use JSON;

our $VERSION = '2.23.0';

# True when the installed Build.pm can not produce nstruct.json itself
sub needed {
    require Lemonldap::NG::Manager::Build;
    return Lemonldap::NG::Manager::Build->can('newStructFile') ? 0 : 1;
}

# build( structFile => $in, newStructFile => $out )
sub build {
    my ( $class, %args ) = @_;
    my ( $in, $out ) = @args{qw(structFile newStructFile)};

    require Lemonldap::NG::Manager::Build;
    require Lemonldap::NG::Manager::Build::CTrees;

    open my $fh, '<', $in or die "Cannot read $in: $!\n";
    my $struct = JSON->new->decode( do { local $/; <$fh> } );
    close $fh;

    # scanTree() is an instance method: Build->new() requires every output
    # file, none of them is written here
    my $builder = Lemonldap::NG::Manager::Build->new(
        map { $_->name => '/dev/null' }
          grep { $_->is_required }
          Lemonldap::NG::Manager::Build->meta->get_all_attributes
    );

    my $enc    = JSON->new->allow_nonref->canonical;
    my $ctrees = Lemonldap::NG::Manager::Build::CTrees::cTrees();
    my %cnodes;
    foreach my $node ( sort keys %$ctrees ) {
        my $tree = [];
        $builder->scanTree( $ctrees->{$node}, $tree, '__KEY__', '' );

        # Same post-processing as struct.json: booleans and numbers are
        # scanned as strings
        my $tmp = $enc->encode($tree);
        $tmp =~ s/"(true|false)"/$1/sg;
        $tmp =~ s/:\s*"(\d+)"\s*(["\}])/:$1$2/sg;
        $cnodes{$node} = $enc->decode($tmp);
    }

    foreach my $node (@$struct) {
        next unless ref $node eq 'HASH' and my $ref = $node->{cnodes};
        ( my $name = $ref ) =~ s/s$//;
        $node->{cnodes} = $cnodes{$name}
          or die "No ctree for cnodes \"$ref\"\n";
    }

    open $fh, '>', $out or die "Cannot write $out: $!\n";
    print $fh $enc->encode($struct);
    close $fh;
    return 1;
}

1;
