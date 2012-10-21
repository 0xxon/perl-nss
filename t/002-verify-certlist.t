use 5.10.1;
use strict;
use warnings;

use Test::More tests=>8;

BEGIN { use_ok( 'NSS' ); }

# load list of root certificates
my $certlist = NSS::CertList->new_from_rootlist('certs/root.ca');
isa_ok($certlist, 'NSS::CertList');

{
	my $selfsigned = NSS::Certificate->new_from_pem(slurp('certs/selfsigned.crt'));
	isa_ok($selfsigned, 'NSS::Certificate');
	ok(!$selfsigned->verify_pkix, 'no verify');
	ok(!$selfsigned->verify_pkix($certlist), 'no verify');
}

# these tests need fixed timestamps added...
# otherwise they will fail in a year or so.

{
	my $rapidssl = NSS::Certificate->new_from_pem(slurp('certs/rapidssl.crt'));
	isa_ok($rapidssl, 'NSS::Certificate');
	ok(!$rapidssl->verify_pkix, 'no verify');
	ok($rapidssl->verify_pkix($certlist), 'verify');
}

# chain verification sadly does not work correctly with certlists.
#
#{
#	my $google = NSS::Certificate->new_from_pem(slurp('certs/google.crt'));
#	isa_ok($google, 'NSS::Certificate');
#	ok(!$google->verify, 'no verify');
#	ok(!$google->verify($certlist), 'no verify');
#
#	# but when we load the thawte intermediate cert too it verifes...
#	
#	{
#		my $thawte = NSS::Certificate->new_from_pem(slurp('certs/thawte.crt'));
#		isa_ok($thawte, 'NSS::Certificate');
#		ok(!$google->verify, 'no verify');
#		ok($google->verify($certlist), 'verify with added thawte');
#	}
#
#	# and out of scope again - no verify anymore
#	ok(!$google->verify, 'no verify');
#	ok(!$google->verify($certlist), 'no verify');
#}

sub slurp {
  local $/=undef;
  open (my $file, shift) or die "Couldn't open file: $!";
  my $string = <$file>;
  close $file;
  return $string;
}
