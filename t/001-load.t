use 5.10.1;
use strict;
use warnings;

use Test::More tests=>8;

BEGIN { use_ok( 'Crypt::NSS' ); }

my $pem = slurp("certs/selfsigned.crt");
my $cert = Crypt::NSS::Certificate->new_from_pem($pem);

isa_ok($cert, 'Crypt::NSS::Certificate');
is($cert->issuer, 'E=email@domain.invalid,CN=Test Certificate,OU=Test Unit,L=Berkeley,ST=California,C=US', 'issuer');
is($cert->subject, 'E=email@domain.invalid,CN=Test Certificate,OU=Test Unit,L=Berkeley,ST=California,C=US', 'subject');
ok($cert->version == 1, 'version == 1');
is($cert->serial, '009863c9c6d7bd0ee5', 'serial');
is($cert->notBefore, 'Mon Oct 15 22:23:31 2012', 'notBefore');
is($cert->notAfter, 'Tue Oct 15 22:23:31 2013', 'notAfter');


sub slurp {
  local $/=undef;
  open (my $file, shift) or die "Couldn't open file: $!";
  my $string = <$file>;
  close $file;
  return $string;
}
