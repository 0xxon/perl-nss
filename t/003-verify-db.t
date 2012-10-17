use 5.10.1;
use strict;
use warnings;

use Test::More tests=>11;

use File::Temp;


BEGIN { 
	# use a temporary directory for our database...
	my $dbdir = File::Temp->newdir();

	use_ok( 'Crypt::NSS', (':dbpath', $dbdir) );
}

# load root certificates to db
Crypt::NSS->load_rootlist('certs/root.ca');

{
	my $selfsigned = Crypt::NSS::Certificate->new_from_pem(slurp('certs/selfsigned.crt'));
	isa_ok($selfsigned, 'Crypt::NSS::Certificate');
	ok(!$selfsigned->verify, 'no verify');
}

# these tests need fixed timestamps added...
# otherwise they will fail in a year or so.

{
	my $rapidssl = Crypt::NSS::Certificate->new_from_pem(slurp('certs/rapidssl.crt'));
	isa_ok($rapidssl, 'Crypt::NSS::Certificate');
	ok($rapidssl->verify, 'verify');
}

# chain verification

{
	my $google = Crypt::NSS::Certificate->new_from_pem(slurp('certs/google.crt'));
	isa_ok($google, 'Crypt::NSS::Certificate');
	ok(!$google->verify, 'no verify');

	# but when we load the thawte intermediate cert too it verifes...
	
	{
		my $thawte = Crypt::NSS::Certificate->new_from_pem(slurp('certs/thawte.crt'));
		isa_ok($thawte, 'Crypt::NSS::Certificate');
		ok($google->verify, 'verify with added thawte');
	}
}

# and apparently due to some magic - the intermediate is now cached, even after all certs 
# have been destroyed.
# be aware of this trickery...
# I guess this is a memory-leak on my part, but I do absolutely not know where

{
	my $google = Crypt::NSS::Certificate->new_from_pem(slurp('certs/google.crt'));
	isa_ok($google, 'Crypt::NSS::Certificate');
	ok($google->verify, 'verify');
}

sub slurp {
  local $/=undef;
  open (my $file, shift) or die "Couldn't open file: $!";
  my $string = <$file>;
  close $file;
  return $string;
}
