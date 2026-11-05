# Copyright: Linagora <https://linagora.com>
# Author   : Xavier Guimard
# License  : GPL-2+
package Lemonldap::NG::Portal::Plugins::Reports;

use strict;
use DBI;
use Date::Parse;
use Date::Format;
use JSON;
use Mouse;

use constant TIMEZONE => undef;    # Use "ZP4" for example for Dubai

extends 'Lemonldap::NG::Portal::Main::Plugin';

# Initialization: declare APIs
sub init {
    my ($self) = @_;

    # Only authentified users can access to this API
    # then manager restrict access to admins only
    $self->addAuthRoute(
        'reports' => {
            apps     => 'appsByUa',
            browsers => 'webUa',
            lastcnx  => 'lastCnx',
        },
        [ 'GET', 'POST' ]
    );
    1;
}

# /reports/apps : send list of User-Agents stored in refresh_token list (Tmail app on phones)
sub appsByUa {
    my ( $self, $req ) = @_;
    return $self->_userAgents( $req,
q"SELECT a_session->>'UA' as UA, count(id) as NB FROM oidcsessions WHERE a_session->>'_type' = 'refresh_token' group by a_session->>'UA' ORDER BY a_session->>'UA'"
    );
}

# /reports/browsers : send list of User-Agents stored in web sessions
sub webUa {
    my ( $self, $req ) = @_;
    return $self->_userAgents( $req,
q"SELECT a_session->>'UA' as UA, count(id) as NB FROM sessions group by a_session->>'UA' ORDER BY a_session->>'UA'"
    );
}

# CSV helpers: fields are always quoted, quotes are doubled (RFC 4180), and
# every value is brought to characters before the response is encoded once.
sub _toChars {
    my ($value) = @_;

    # Net::LDAP returns bytes and DBD::Pg returns characters when pg_enable_utf8
    # is set (its default), so a non-UTF-8 flag means raw UTF-8 bytes. This is
    # the same assumption as in #212: the flag is only trusted for that case.
    my $copy = defined $value ? "$value" : '';
    utf8::decode($copy) unless utf8::is_utf8($copy);
    return $copy;
}

sub _csvField {
    my ($value) = @_;
    my $field = _toChars($value);

    # Spreadsheets evaluate a quoted cell as a formula too, so neutralise the
    # OWASP CSV Injection prefixes before quoting. The count column never
    # starts with one of these characters.
    $field = "'$field" if $field =~ /^[=+\-\@\t\r]/;
    $field =~ s/"/""/g;
    return qq("$field");
}

sub _csvRow {
    return join( ';', map { _csvField($_) } @_ ) . "\n";
}

sub _csvResponse {
    my ( $self, $csv ) = @_;
    utf8::encode($csv);
    return [
        200,
        [
            'Content-Type'   => 'text/csv; charset=utf-8',
            'Content-Length' => length($csv),
        ],
        [$csv],
    ];
}

# Common internal method to build CSV from a query
sub _userAgents {
    my ( $self, $req, $query ) = @_;
    my $data = eval { $self->queryDb($query) };
    return $self->p->sendError( $req, $@ ) if $@;
    my $csv = _csvRow( 'User Agent', 'Count' );
    my $uas = {};
    foreach my $row (@$data) {
        my ( $ua, $c ) = @$row;
        next unless $ua and $c and $c =~ /^\d+$/;
        $uas->{ transformUa($ua) } += $c;
    }
    foreach my $key ( sort keys %$uas ) {
        $csv .= _csvRow( $key, $uas->{$key} );
    }
    return $self->_csvResponse($csv);
}

# Internal method to query sessions database
sub queryDb {
    my ( $self, $query ) = @_;
    my $dbi = $self->conf->{globalStorageOptions};
    my $dbh =
      DBI->connect( $dbi->{DataSource}, $dbi->{UserName}, $dbi->{Password} )
      or die "No access to DB";
    my $sth = $dbh->prepare($query);
    $sth->execute;
    return $sth->fetchall_arrayref;
}

# /reports/lastcnx : last conexion for each user (web or IMAP/SMTP)
sub lastCnx {
    my ( $self, $req ) = @_;
    my $j = JSON->new;

    # Collect last web connections from SSO database
    my $queryResult = eval {
        $self->queryDb(
q"SELECT a_session->>'_session_uid' AS uid, a_session->>'_loginHistory' AS t FROM psessions"
        );
    };
    my $res  = {};
    my $data = {};
    foreach my $row (@$queryResult) {
        eval {
            my $tmp = $j->decode( $row->[1] )->{successLogin}->[0]->{_utime};
            $res->{ $row->[0] } = $tmp if $tmp;
        };
    }

    # Collect last IMAP/SMTP connexion from LDAP
    my $uLdap =
      $self->p->{loadedModules}->{'Lemonldap::NG::Portal::UserDB::LDAP'};
    $uLdap->validateLdap;
    my $mesg = $uLdap->ldap->search(
        base   => $self->conf->{ldapBase},
        filter => '(uid=*)',
        attrs  => [qw(uid pwdLastSuccess givenName sn twakeDepartmentPath)],
    );
    $mesg->code
      and return $self->p->sendError( $req, 'Failed to conect to LDAP' );
    foreach my $entry ( $mesg->entries ) {
        my $uid = $entry->get_value('uid');
        my $ts  = $entry->get_value('pwdLastSuccess');
        if (    $ts
            and $ts =~
s/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?/$1-$2-$3T$4:$5:$6.0000000/
          )
        {
            $ts = str2time($ts);
            $res->{$uid} = $ts if !$res->{$uid} or $res->{$uid} < $ts;
        }
        push @{ $data->{$uid} }, ( $entry->get_value($_) || '' )
          foreach (qw(givenName sn twakeDepartmentPath));
        $res->{$uid} = 0 unless $res->{$uid};
    }

    # Build response in CSV format
    my $csv =
      _csvRow( 'UID', 'Last connection', 'Givenname', 'Surname', 'Department' );
    foreach my $uid ( sort { $res->{$a} <=> $res->{$b} } keys %$res ) {
        my @attrs = @{ $data->{$uid} || [] };
        push @attrs, '' while @attrs < 3;
        my $last =
          $res->{$uid} ? time2str( '%c', $res->{$uid}, TIMEZONE ) : 'never';
        $csv .= _csvRow( $uid, $last, @attrs[ 0 .. 2 ] );
    }

    return $self->_csvResponse($csv);
}

sub browser {
    my ($rest) = @_;
    my ($br)   = ( $rest =~ m#(Chrome/\d[\.\d]*)# );
    $br =~ s#/# # if $br;
    return "Edge $1"            if $rest =~ m#(?:EdgA?)/(\d[\.\d]*)#;
    return "Opera $1"           if $rest =~ m#(?:OPR)/(\d[\.\d]*)#;
    return "Samsung Browser $1" if $rest =~ m#SamsungBrowser/(\S+)#;
    return "Firefox $1"         if $rest =~ m#Firefox/(\d[\.\d]*)$#;
    return "Safari $1"
      if $rest =~ m#Version/(\d[\.\d]*)\s+(?:.*\s+)?Safari/(\d[\.\d]*)$#;
    return "Chrome $1"
      if $rest =~
      m#(?:Chrome|CriOS)/(\d[\.\d]*)\s+(?:.*\s+)?Safari/(\d[\.\d]*)$#;
    return "GSA $1"
      if $rest =~ m#GSA/(\d[\.\d]*)\s+(?:.*\s+)?Safari/(\d[\.\d]*)$#;
    return $br if $br;
    return "Unknown $rest";
}

sub transformUa {
    my ($ua) = @_;
    my %v = ( 95 => '0.14.1', 96 => '0.14.2' );
    my $res =
        $ua =~ m#^TMail/(\d+).*Darwin# ? "iOS - Tmail app " . ( $v{$1} || $1 )
      : $ua =~ m#^TwakeMailNSE/(\d[\.\d]+).*(iOS \d[\.\d]+)#
      ? "$2 - Tmail app $1"
      : $ua =~ /^LLNG-CLient/ ? 'Internal request'
      :                         '';
    return $res if $res;
    return $ua unless $ua =~ m#^(.*?)/(\d[\.\d]*)\s+\((.*?)\)\s*(.*)$#;
    my ( $main, $mver, $os, $rest ) = ( $1, $2, $3, $4 );
    my $browser = browser($rest);
    if ( $os =~ s/^(?:.*\s)?Android\s+(\d[\.\d]*);\s*// ) {
        $res = "Android $1";
        return "Samsung $1 $res" if $os =~ /^(?:SAMSUNG\s+)?(SM\S+)/;
        return "Huawei $1 $res"  if $os =~ m#Build/HUAWEI(\S+)#;

#return "Huawei $1 $res" if $os =~ /^((?:HEY|RMO|CLK|CRT|ELP|LLY|REA|BVL|EXE|FRL|JNY|MGA|BNE|MAO|NAM|NCO)-\S+)/;
        return "Huawei $1 $res"       if $os =~ /^([A-Z]{3}-\S+)/;
        return "Xiaomi $1 $res"       if $os =~ /^(Mi\s+\S+)/;
        return "OPPO $1 $res"         if $os =~ /^(CPH\S+)/;
        return "LG $1 $res"           if $os =~ /^(LM-\S+)/;
        return "Realme $1 $res"       if $os =~ /^(RMX\S+)/;
        return "Google $1 $res"       if $os =~ /^(Pixel\s+\S+)/;
        return "ASUS $1 $res"         if $os =~ /^(ASUS\S+)/;
        return "Zeki $1 $res"         if $os =~ /^(TB\S+)/;
        return "Motorola $1 $res"     if $os =~ /^(moto\s+\S+)/;
        return "BlackBerry $1 $res"   if $os =~ /^(BBE\S+)/;
        return "Xiaomi Redmi $1 $res" if $os =~ /^Redmi\s+(\d[\.\d]*)/;
        return "Firefox $1 $res "     if $os =~ /^Mobile; rv:(\d[\.\d]*)$/;

        if ( $os eq 'K' ) {
            return "$browser $res";
        }
        return "$1 $res"
          if $os =~ /^((?:ONEPLUS|Redmi Note|Hisense Infinity) \S+)/;
        return "Unknown $res"
          . ( $browser and $browser !~ /Unknown/i ? " (maybe $browser)" : '' );
    }
    if ( $os =~ /^(?:Macintosh; .*Mac OS X (\d[\.\d_]*))/ ) {
        return "$browser Apple Macintosh Mac OS $1";
    }
    if ( $os =~ /^Windows\s((?:NT\s)?\d[\.\d]*)/ ) {
        return "$browser MS Windows $1";
    }
    if ( $os =~ /\bCrOS (?:\S+\s+)?(\S+)\b/ ) {
        return "$browser Chromium OS $1";
    }
    if ( $os =~ /\bLinux (\S+)\b/ ) {
        return "$browser Linux $1";
    }
    if ( $os =~ /^(iPad|iPhone).*? (\d[\.\d_]*)\b/ ) {
        return "$browser Apple $1 iOS $2";
    }
    return $ua;
}

1;
