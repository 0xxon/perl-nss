use 5.10.1;
use strict;
use warnings;

use Test::More tests=>30;

use File::Temp;

my $dbdir;

my $vfytime = 1351057173; # time at which certificates were valid
my $invalidtime = 42; # well, certainly not valid here.

BEGIN { 
	# use a temporary directory for our database...
	$dbdir = File::Temp->newdir();

	use_ok( 'NSS', (':dbpath', $dbdir) );
}

# load root certificates to db
NSS->load_rootlist('certs/root.ca');

{
	my $selfsigned = NSS::Certificate->new_from_pem(slurp('certs/selfsigned.crt'));
	isa_ok($selfsigned, 'NSS::Certificate');
	ok(!$selfsigned->verify_pkix($vfytime), 'no verify');
	ok(!$selfsigned->verify_cert($vfytime), 'no verify');
	ok(!$selfsigned->verify_certificate($vfytime), 'no verify');
	ok(!$selfsigned->verify_certificate_pkix($vfytime), 'no verify');
}

{
	my $rapidssl = NSS::Certificate->new_from_pem(slurp('certs/rapidssl.crt'));
	isa_ok($rapidssl, 'NSS::Certificate');
	ok($rapidssl->verify_pkix($vfytime), 'verify');
	ok($rapidssl->verify_cert($vfytime), 'verify');
	ok($rapidssl->verify_certificate($vfytime), 'verify');
	ok($rapidssl->verify_certificate_pkix($vfytime), 'verify');
	
	# but not with invalid time
	
	ok(!$rapidssl->verify_pkix($invalidtime), 'no verify');
	ok(!$rapidssl->verify_cert($invalidtime), 'no verify');
	ok(!$rapidssl->verify_certificate($invalidtime), 'no verify');
	ok(!$rapidssl->verify_certificate_pkix($invalidtime), 'no verify');
}

# chain verification

{
	my $google = NSS::Certificate->new_from_pem(slurp('certs/google.crt'));
	isa_ok($google, 'NSS::Certificate');
	ok(!$google->verify_pkix($vfytime), 'no verify');
	ok(!$google->verify_cert($vfytime), 'no verify');
	ok(!$google->verify_certificate($vfytime), 'no verify');
	ok(!$google->verify_certificate_pkix($vfytime), 'no verify');

	# but when we load the thawte intermediate cert too it verifes...
	
	{
		my $thawte = NSS::Certificate->new_from_pem(slurp('certs/thawte.crt'));
		isa_ok($thawte, 'NSS::Certificate');
		ok($google->verify_pkix($vfytime), 'verify with added thawte');
		ok($google->verify_cert($vfytime), 'verify with added thawte');
		ok($google->verify_certificate($vfytime), 'verify with added thawte');
		ok($google->verify_certificate_pkix($vfytime), 'verify with added thawte');
	}
}

# and apparently due to some magic - the intermediate is now cached, even after all certs 
# have been destroyed.
# be aware of this trickery...
# I guess this is a memory-leak on my part, but I do absolutely not know where

# Dirty fix: reinit NSS
NSS::_reinit();

{
	my $google = NSS::Certificate->new_from_pem(slurp('certs/google.crt'));
	isa_ok($google, 'NSS::Certificate');
	ok(!$google->verify_pkix($vfytime), 'no verify');
	ok(!$google->verify_cert($vfytime), 'no verify');
	ok(!$google->verify_certificate($vfytime), 'no verify');
	ok(!$google->verify_certificate_pkix($vfytime), 'no verify');
}

sub slurp {
  local $/=undef;
  open (my $file, shift) or die "Couldn't open file: $!";
  my $string = <$file>;
  close $file;
  return $string;
}
