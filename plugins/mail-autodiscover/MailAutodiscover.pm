# Copyright: Linagora <https://linagora.com>
# Author   : Xavier Guimard
# License  : GPL-2+
package Lemonldap::NG::Portal::Plugins::MailAutodiscover;

use strict;
use Mouse;

extends 'Lemonldap::NG::Portal::Main::Plugin';

our $imapServer = 'imap.mydomain.tld';
our $smtpServer = 'smtp.mydomain.tld';

my $autodiscover = <<EOF;
<?xml version="1.0" encoding="utf-8" ?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
 <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
  <Account>
   <AccountType>email</AccountType>
   <Action>settings</Action>
   <Protocol>
    <Type>IMAP</Type>
    <Server>$imapServer</Server>
    <Port>993</Port>
    <DomainRequired>off</DomainRequired>
    <LoginName>%EMAILADDRESS%</LoginName>
    <SPA>off</SPA>
    <SSL>on</SSL>
    <AuthRequired>on</AuthRequired>
   </Protocol>
   <Protocol>
    <Type>SMTP</Type>
    <Server>$smtpServer</Server>
    <Port>465</Port>
    <DomainRequired>off</DomainRequired>
    <LoginName>%EMAILADDRESS%</LoginName>
    <SPA>off</SPA>
    <Encryption>SSL</Encryption>
    <AuthRequired>on</AuthRequired>
    <UsePOPAuth>off</UsePOPAuth>
    <SMTPLast>off</SMTPLast>
   </Protocol>
  </Account>
 </Response>
</Autodiscover>
EOF

my $validEmail =
qr#^(?:(?^u:(?:(?^u:(?>(?^u:(?^u:(?>(?^u:(?>(?^u:(?>(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*[^\x00-\x1F\x7F()<>\[\]:;@\\,."\s]+(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*))|\.|\s*"(?^u:(?^u:[^\\"])|(?^u:\\(?^u:[^\x0A\x0D])))+"\s*))+))|(?>(?^u:(?^u:(?>(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*[^\x00-\x1F\x7F()<>\[\]:;@\\,."\s]+(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*))|(?^u:(?>(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*"(?^u:(?^u:[^\\"])|(?^u:\\(?^u:[^\x0A\x0D])))*"(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*)))+))?)(?^u:(?>(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*<(?^u:(?^u:(?^u:(?>(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*(?^u:(?>[^\x00-\x1F\x7F()<>\[\]:;@\\,."\s]+(?:\.[^\x00-\x1F\x7F()<>\[\]:;@\\,."\s]+)*))(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*))|(?^u:(?>(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*"(?^u:(?^u:[^\\"])|(?^u:\\(?^u:[^\x0A\x0D])))*"(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*)))\@(?^u:(?^u:(?>(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*(?^u:(?>[^\x00-\x1F\x7F()<>\[\]:;@\\,."\s]+(?:\.[^\x00-\x1F\x7F()<>\[\]:;@\\,."\s]+)*))(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*))|(?^u:(?>(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*\[(?:\s*(?^u:(?^u:[^\[\]\\])|(?^u:\\(?^u:[^\x0A\x0D]))))*\s*\](?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*))))>(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*)))|(?^u:(?^u:(?^u:(?>(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*(?^u:(?>[^\x00-\x1F\x7F()<>\[\]:;@\\,."\s]+(?:\.[^\x00-\x1F\x7F()<>\[\]:;@\\,."\s]+)*))(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*))|(?^u:(?>(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*"(?^u:(?^u:[^\\"])|(?^u:\\(?^u:[^\x0A\x0D])))*"(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*)))\@(?^u:(?^u:(?>(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*(?^u:(?>[^\x00-\x1F\x7F()<>\[\]:;@\\,."\s]+(?:\.[^\x00-\x1F\x7F()<>\[\]:;@\\,."\s]+)*))(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*))|(?^u:(?>(?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*\[(?:\s*(?^u:(?^u:[^\[\]\\])|(?^u:\\(?^u:[^\x0A\x0D]))))*\s*\](?^u:(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))|(?>\s+))*)))))(?>(?^u:(?>\s*\((?:\s*(?^u:(?^u:(?>[^()\\]+))|(?^u:\\(?^u:[^\x0A\x0D]))|))*\s*\)\s*))*)))$#o;

sub init {
    my ($self) = @_;
    $self->addUnauthRoute(
        autodiscover => {
            'autodiscover.json' => 'notFound',
            'autodiscover.xml'  => 'autodiscover',
        },
        [ 'GET', 'POST' ]
    )->addUnauthRoute(
        EWS => 'notFound',
        [ 'GET', 'POST' ]
    )->addAuthRoute(
        autodiscover => {
            'autodiscover.json' => 'notFound',
            'autodiscover.xml'  => 'autodiscover',
        },
        [ 'GET', 'POST' ]
    );
}

sub autodiscover {
    my ( $self, $req ) = @_;
    my $data = $autodiscover;
    my $mail = $req->param('email');
    $mail = '%EMAILADDRESS%' unless $mail and $mail =~ $validEmail;
    $data =~ s/%EMAILADDRESS%/$mail/sg;

    return [
        200,
        [
            'Content-Type'   => 'application/xml',
            'Content-Length' => length($data)
        ],
        [$data]
    ];
}

our $NOTFOUND = '<html><body>Not found...</body></html>';

sub notFound {
    return [
        404,
        [
            'Content-Type'   => 'text/html',
            'Content-Length' => length($NOTFOUND)
        ],
        [$NOTFOUND]
    ];
}

1;
