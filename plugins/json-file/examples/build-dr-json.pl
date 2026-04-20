#!/usr/bin/perl

# Example: build a UserDB::JsonFile users file from the current
# LemonLDAP::NG config and LDAP backend.
#
# This script is NOT part of the plugin runtime. It is provided as a
# starting point that you can adapt to your own needs — typically as a
# cron that snapshots a fixed list of administrators so that, in case of
# LDAP outage, the portal can be switched to `authentication: GPG` +
# `userDB: JsonFile` and the admins keep their usual attributes and
# groups to repair the platform.
#
# Inspired by lemonldap-ng-portal/scripts/llngUserAttributes.

use strict;
use warnings;
use Getopt::Long;
use JSON;
use Lemonldap::NG::Common::FormEncode;
use Lemonldap::NG::Portal;
use Lemonldap::NG::Portal::Main::Constants qw(portalConsts);

my %opts = (
    f          => 'uid',
    'key-by'   => 'mail',
    loglevel   => 'error',
);
GetOptions( \%opts,
    'h|help', 'f|field=s', 'key-by=s', 'd|debug', 'loglevel=s',
    'map-file=s',
) or usage(1);

usage(0) if $opts{h};
usage(1) unless @ARGV || $opts{'map-file'};

# Mapping: LDAP lookup value -> user key to emit in the JSON (typically
# the GPG-key mail). Built from --map-file and inline "lookup=key" pairs.
my %map;
my @admins;

if ( my $f = $opts{'map-file'} ) {
    open my $fh, '<', $f or die "Cannot open map file $f: $!\n";
    while ( my $line = <$fh> ) {
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '' || $line =~ /^#/;
        my ( $lookup, $key ) = split /\s*[=,;\s]\s*/, $line, 2;
        unless ( defined $lookup && length $lookup
              && defined $key    && length $key )
        {
            warn "Ignoring malformed line in $f: $line\n";
            next;
        }
        $map{$lookup} = $key;
        push @admins, $lookup;
    }
    close $fh;
}

for my $arg (@ARGV) {
    my ( $lookup, $key ) = split /=/, $arg, 2;
    push @admins, $lookup;
    $map{$lookup} = $key if defined $key && length $key;
}

sub usage {
    my $rc = shift;
    my $fh = $rc ? *STDERR : *STDOUT;
    print $fh <<"EOF";
Build a UserDB::JsonFile document from LemonLDAP::NG + LDAP, for a fixed
list of administrators.

Usage:
  $0 [options] admin1[=userkey1] [admin2[=userkey2] ...] > users.json
  $0 [options] --map-file=FILE > users.json

Options:
  -f, --field=ATTR   lookup attribute for each command-line argument
                     (default: uid)
  --key-by=ATTR      fallback session attribute used as the JSON user key
                     when no explicit mapping is given
                     (default: mail, matches Auth::GPG's \$req->user)
  --map-file=FILE    read "lookup <sep> userkey" pairs from FILE
                     (separator: '=', ',', ';' or whitespace; '#' for
                     comments). Each lookup is resolved against LDAP with
                     --field, and the JSON key is set to userkey (e.g.
                     the GPG identity mail of that admin).
  -d, --debug        enable debug logging
  --loglevel=LEVEL   force a log level (default: error)
  -h, --help         show this help

Example:
  $0 xguimard=yadd\@debian.org alice=alice\@keys.example
  $0 --map-file=/etc/lemonldap-ng/dr-admins.map

The output structure is:
  {
    "users":  { "<key-by value>": { ...session attributes... } },
    "groups": { "<group name>": [ "<key-by value>", ... ] }
  }

Only attributes that can be rebuilt by UserDB::JsonFile are kept. Runtime
fields (\_auth, \_user, \_session_id, ipAddr, UA, authenticationLevel,
login history, etc.) are stripped.
EOF
    exit $rc;
}

my $p = Lemonldap::NG::Portal->new;
$p->init( {
    logLevel                    => $opts{d} ? 'debug' : $opts{loglevel},
    findUser                    => 1,
    findUserSearchingAttributes => { "$opts{f}##1" => 'Login' },
} );

my %users;          # JSON "users" section
my %groupMembers;   # groupName => { userKey => 1 }
my $overallExit = 0;

for my $lookup (@admins) {
    my $si = resolveUser($lookup);
    unless ($si) {
        warn "[$lookup] no session info returned, skipped\n";
        $overallExit ||= 1;
        next;
    }

    my $key = $map{$lookup} // $si->{ $opts{'key-by'} };
    unless ( defined $key && length $key ) {
        warn "[$lookup] no mapping and no value for --key-by "
          . "'$opts{'key-by'}', skipped\n";
        $overallExit ||= 1;
        next;
    }

    if ( my $hg = $si->{hGroups} ) {
        $groupMembers{$_}{$key} = 1 for keys %$hg;
    }

    $users{$key} = filterAttrs($si);
}

my %groups = map { $_ => [ sort keys %{ $groupMembers{$_} } ] }
    keys %groupMembers;

print JSON->new->canonical->pretty->encode( {
    users  => \%users,
    groups => \%groups,
} );

exit $overallExit;

sub resolveUser {
    my $id  = shift;
    my $req = Lemonldap::NG::Portal::Main::Request->new( {
        REQUEST_URI  => '/',
        REMOTE_ADDR  => '127.0.0.1',
        PATH_INFO    => '/',
        QUERY_STRING => build_urlencoded( $opts{f} => $id ),
    } );
    $req->init( {} );
    $req->data->{_pwdcheck} = 1;
    $req->user($id);
    $req->steps( [
        'getUser',        @{ $p->betweenAuthAndData },
        'setSessionInfo', $p->groupsAndMacros,
        'setLocalGroups',
    ] );
    my $rc = $p->process($req);
    if ($rc) {
        warn "[$id] pipeline returned "
          . ( portalConsts->{$rc} // $rc ) . "\n";
        $overallExit ||= $rc;
    }
    return $req->sessionInfo;
}

sub filterAttrs {
    my $si = shift;
    my %out;
    for my $k ( keys %$si ) {
        next if $k =~ /^_/;                 # internal (_user, _dn, _auth, …)
        next if $k eq 'groups';             # rebuilt by Demo::setGroups
        next if $k eq 'hGroups';            # idem
        next if $k eq 'ipAddr' || $k eq 'UA';
        next if $k eq 'authenticationLevel';
        my $v = $si->{$k};
        next unless defined $v;
        next if ref $v;                     # loginHistory etc.
        next if $v eq '';
        $out{$k} = $v;
    }
    return \%out;
}
