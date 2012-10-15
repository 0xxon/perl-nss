use 5.10.1;
use strict;
use warnings;

use Test::More tests=>4;

BEGIN { use_ok( 'Crypt::NSS' ); }

my $pem = slurp("server.crt");
my $cert = Crypt::NSS::Certificate->new_from_pem($pem);

isa_ok($cert, 'Crypt::NSS::Certificate');
is($cert->issuer, 'E=email@domain.invalid,CN=Test Certificate,OU=Test Unit,L=Berkeley,ST=California,C=US');
is($cert->subject, 'E=email@domain.invalid,CN=Test Certificate,OU=Test Unit,L=Berkeley,ST=California,C=US');



sub slurp {
  local $/=undef;
  open (my $file, shift) or die "Couldn't open file: $!";
  my $string = <$file>;
  close $file;
  return $string;
}
