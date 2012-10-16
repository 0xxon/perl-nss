use 5.10.1;
use strict;
use warnings;

use Test::More tests=>8;

BEGIN { use_ok( 'Crypt::NSS' ); }

# load list of root certificates
my $certlist = Crypt::NSS::CertList->new_from_rootlist('certs/root.ca');
isa_ok($certlist, 'Crypt::NSS::CertList');

{
	my $selfsigned = Crypt::NSS::Certificate->new_from_pem(slurp('certs/selfsigned.crt'));
	isa_ok($selfsigned, 'Crypt::NSS::Certificate');
	ok(!$selfsigned->verify, 'no verify');
	ok(!$selfsigned->verify($certlist), 'no verify');
}

# these tests need fixed timestamps added...
# otherwise they will fail in a year or so.

{
	my $rapidssl = Crypt::NSS::Certificate->new_from_pem(slurp('certs/rapidssl.crt'));
	isa_ok($rapidssl, 'Crypt::NSS::Certificate');
	ok(!$rapidssl->verify, 'no verify');
	ok($rapidssl->verify($certlist), 'verify');
}

# chain verification sadly does not work correctly with certlists.
#
#{
#	my $google = Crypt::NSS::Certificate->new_from_pem(slurp('certs/google.crt'));
#	isa_ok($google, 'Crypt::NSS::Certificate');
#	ok(!$google->verify, 'no verify');
#	ok(!$google->verify($certlist), 'no verify');
#
#	# but when we load the thawte intermediate cert too it verifes...
#	
#	{
#		my $thawte = Crypt::NSS::Certificate->new_from_pem(slurp('certs/thawte.crt'));
#		isa_ok($thawte, 'Crypt::NSS::Certificate');
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
