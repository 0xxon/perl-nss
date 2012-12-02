package Crypt::NSS::X509::CRL;

use strict;
use warnings;

use Crypt::NSS::X509;

sub new_from_pem {
	my $class = shift;
	my $pem = shift;

	$pem =~ s/-+BEGIN.*CRL-+// or die("Could not find crl start");
	$pem =~ s/-+END.*CRL-+// or die("Could not find crl end");

	my $der = MIME::Base64::decode($pem);
	if ( length($der) < 1 ) {
		die("Could not decode crl");
	}

	return $class->new_from_der($der, @_);
}

1;
