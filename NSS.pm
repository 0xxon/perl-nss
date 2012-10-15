package Crypt::NSS;

use strict;

use 5.10.1;

use vars qw($VERSION @EXPORT_OK);
use Exporter;
use base qw(Exporter);

use autodie qw(open close);

$VERSION = '0.1';

@EXPORT_OK = qw(
);


BOOT_XS: {
  require DynaLoader;

  # DynaLoader calls dl_load_flags as a static method.
  *dl_load_flags = DynaLoader->can('dl_load_flags');

  do {__PACKAGE__->can('bootstrap') || \&DynaLoader::bootstrap}->(__PACKAGE__, $VERSION);
}

sub load_rootlist {
	my ($class, $filename) = @_;

	my $cert;

	open (my $fh, "<", $filename);
	while ( my $line = <> ) {
		if ( $line =~ /--BEGIN CERTIFICATE--/ .. /--END CERTIFICATE--/ ) {
			print $line;
		}
	}

	close($fh);
}

package Crypt::NSS::Certificate;
use MIME::Base64 ();

sub new_from_pem {
	my ($class, $pem) = @_;

	$pem =~ s/-----BEGIN CERTIFICATE-----// or die("Did not found certificate start");
	$pem =~ s/-----END CERTIFICATE-----// or die ("Did not found certificate end");

	my $der = MIME::Base64::decode($pem);
	if ( length($der) < 1 ) {
		die("Could not decode certificate");
	}

	return $class->new($der);
}


END {
}

1;

__END__

=head1 NAME

Crypt::NSS - Perl interface for the certificate handling parts of the NSS api.

=head1 SYNOPSIS

  use Crypt::NSS;

  my $cert = Crypt::NSS::Certificate->new($der);

  print $x509->subject() . "\n";
  print $x509->issuer() . "\n";

  my $valid = $cert->validate();


=head1 ABSTRACT

  Crypt::NSS - Perl interface for the certificate handling parts of the NSS api..

=head1 DESCRIPTION

=head2 EXPORT

None.

=head1 FUNCTIONS

=head1 SEE ALSO

OpenSSL(1), Crypt::X509

=head1 AUTHOR

Johanna Amann, E<lt>johanna@icir.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2012 by Johanna Amann

This library is free software and licensed under the GNU LGPL, version 2.1
as available at http://www.gnu.org/licenses/lgpl-2.1.html.

The library contains source code of the Mozilla Network Security Services; for
NSS license information please see http://www.mozilla.org/projects/security/pki/nss/.

=cut
