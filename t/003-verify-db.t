use 5.10.1;
use strict;
use warnings;

use Test::More tests=>26;

use File::Temp;

my $dbdir;

BEGIN { 
	# use a temporary directory for our database...
	$dbdir = File::Temp->newdir();

	use_ok( 'Crypt::NSS', (':dbpath', $dbdir) );
}

# load root certificates to db
Crypt::NSS->load_rootlist('certs/root.ca');

{
	my $selfsigned = Crypt::NSS::Certificate->new_from_pem(slurp('certs/selfsigned.crt'));
	isa_ok($selfsigned, 'Crypt::NSS::Certificate');
	ok(!$selfsigned->verify_pkix, 'no verify');
	ok(!$selfsigned->verify_cert, 'no verify');
	ok(!$selfsigned->verify_certificate, 'no verify');
	ok(!$selfsigned->verify_certificate_pkix, 'no verify');
}

# these tests need fixed timestamps added...
# otherwise they will fail in a year or so.

{
	my $rapidssl = Crypt::NSS::Certificate->new_from_pem(slurp('certs/rapidssl.crt'));
	isa_ok($rapidssl, 'Crypt::NSS::Certificate');
	ok($rapidssl->verify_pkix, 'verify');
	ok($rapidssl->verify_cert, 'verify');
	ok($rapidssl->verify_certificate, 'verify');
	ok($rapidssl->verify_certificate_pkix, 'verify');
}

# chain verification

{
	my $google = Crypt::NSS::Certificate->new_from_pem(slurp('certs/google.crt'));
	isa_ok($google, 'Crypt::NSS::Certificate');
	ok(!$google->verify_pkix, 'no verify');
	ok(!$google->verify_cert, 'no verify');
	ok(!$google->verify_certificate, 'no verify');
	ok(!$google->verify_certificate_pkix, 'no verify');

	# but when we load the thawte intermediate cert too it verifes...
	
	{
		my $thawte = Crypt::NSS::Certificate->new_from_pem(slurp('certs/thawte.crt'));
		isa_ok($thawte, 'Crypt::NSS::Certificate');
		ok($google->verify_pkix, 'verify with added thawte');
		ok($google->verify_cert, 'verify with added thawte');
		ok($google->verify_certificate, 'verify with added thawte');
		ok($google->verify_certificate_pkix, 'verify with added thawte');
	}
}

# and apparently due to some magic - the intermediate is now cached, even after all certs 
# have been destroyed.
# be aware of this trickery...
# I guess this is a memory-leak on my part, but I do absolutely not know where

# Dirty fix: reinit NSS
Crypt::NSS::_reinit();

{
	my $google = Crypt::NSS::Certificate->new_from_pem(slurp('certs/google.crt'));
	isa_ok($google, 'Crypt::NSS::Certificate');
	ok(!$google->verify_pkix, 'no verify');
	ok(!$google->verify_cert, 'no verify');
	ok(!$google->verify_certificate, 'no verify');
	ok(!$google->verify_certificate_pkix, 'no verify');
}

sub slurp {
  local $/=undef;
  open (my $file, shift) or die "Couldn't open file: $!";
  my $string = <$file>;
  close $file;
  return $string;
}
