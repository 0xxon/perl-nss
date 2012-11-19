use 5.10.1;
use strict;
use warnings;

use Test::More tests=>10;

BEGIN { use_ok( 'NSS' ); }

my $der = slurp("certs/rfc3280bis_cert1.cer");
my $cert = NSS::Certificate->new($der);

isa_ok($cert, 'NSS::Certificate');
is($cert->subject, 'CN=Example CA,DC=example,DC=com', 'subject');

$der = slurp("certs/thawte.crt");
my $thawte = NSS::Certificate->new_from_pem($der);
isa_ok($thawte, 'NSS::Certificate');
is($thawte->subject, 'CN=Thawte SGC CA,O=Thawte Consulting (Pty) Ltd.,C=ZA', 'subject');

my $crlder = slurp("certs/rfc3280bis_CRL.crl");
my $crl = NSS::CRL->new_from_der($crlder);

isa_ok($crl, 'NSS::CRL');
ok($crl->verify($cert, 1104537600), 'verify crl');
ok(!$crl->verify($thawte, 1104537600), 'verify crl');

my @entries = $crl->entries;
ok(scalar @entries == 1, '1 entry');
ok($entries[0]->serial == 12, 'crl entry serial');

sub slurp {
  local $/=undef;
  open (my $file, shift) or die "Couldn't open file: $!";
  my $string = <$file>;
  close $file;
  return $string;
}
