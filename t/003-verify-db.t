use 5.10.1;
use strict;
use warnings;

use Test::More tests=>36;

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
	# lol. The different verify operatins give different 
	is($selfsigned->verify_pkix($vfytime), -8179, 'no verify');
	is($selfsigned->verify_cert($vfytime), -8172, 'no verify');
	is($selfsigned->verify_certificate($vfytime), -8172, 'no verify');
	is($selfsigned->verify_certificate_pkix($vfytime), -8179, 'no verify');
}

{
	my $rapidssl = NSS::Certificate->new_from_pem(slurp('certs/rapidssl.crt'));
	isa_ok($rapidssl, 'NSS::Certificate');
	is($rapidssl->verify_pkix($vfytime), 1, 'verify');
	is($rapidssl->verify_cert($vfytime), 1, 'verify');
	is($rapidssl->verify_certificate($vfytime), 1, 'verify');
	is($rapidssl->verify_certificate_pkix($vfytime), 1, 'verify');
	
	# but not with invalid time
	
	is($rapidssl->verify_pkix($invalidtime), -8181, 'no verify');
	is($rapidssl->verify_cert($invalidtime), -8181, 'no verify');
	# Fun. Those apparently try chain resolution before date checking
	is($rapidssl->verify_certificate($invalidtime), -8179, 'no verify');
	is($rapidssl->verify_certificate_pkix($invalidtime), -8179, 'no verify');
}

# chain verification

{
	my $google = NSS::Certificate->new_from_pem(slurp('certs/google.crt'));
	isa_ok($google, 'NSS::Certificate');
	# something they agree on. At last.
	is($google->verify_pkix($vfytime), -8179, 'no verify');
	is($google->verify_cert($vfytime), -8179, 'no verify');
	is($google->verify_certificate($vfytime), -8179, 'no verify');
	is($google->verify_certificate_pkix($vfytime), -8179, 'no verify');

	# but when we load the thawte intermediate cert too it verifes...
	
	{
		my $thawte = NSS::Certificate->new_from_pem(slurp('certs/thawte.crt'));
		isa_ok($thawte, 'NSS::Certificate');
		is($google->verify_pkix($vfytime), 1, 'verify with added thawte');
		is($google->verify_cert($vfytime), 1, 'verify with added thawte');
		is($google->verify_certificate($vfytime), 1, 'verify with added thawte');
		is($google->verify_certificate_pkix($vfytime), 1, 'verify with added thawte');
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
	is($google->verify_pkix($vfytime), -8179, 'no verify');
	is($google->verify_cert($vfytime), -8179, 'no verify');
	is($google->verify_certificate($vfytime), -8179, 'no verify');
	is($google->verify_certificate_pkix($vfytime), -8179, 'no verify');
}

{
	# now, let's add the thawte-cert to the db
	my $thawte = NSS::Certificate->new_from_pem(slurp('certs/thawte.crt'));
	isa_ok($thawte, 'NSS::Certificate');
	NSS::add_cert_to_db($thawte, $thawte->subject);
}

# kill NSS again
#
NSS::_reinit();

# and this time it should validate
{
	my $google = NSS::Certificate->new_from_pem(slurp('certs/google.crt'));
	isa_ok($google, 'NSS::Certificate');
	is($google->verify_pkix($vfytime), 1, 'verify');
	is($google->verify_cert($vfytime), 1, 'verify');
	is($google->verify_certificate($vfytime), 1, 'verify');
	is($google->verify_certificate_pkix($vfytime), 1, 'verify');
}
	

sub slurp {
  local $/=undef;
  open (my $file, shift) or die "Couldn't open file: $!";
  my $string = <$file>;
  close $file;
  return $string;
}
