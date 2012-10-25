package NSS;

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

	my $pem;

	open (my $fh, "<", $filename);
	while ( my $line = <$fh> ) {
		if ( $line =~ /--BEGIN CERTIFICATE--/ .. $line =~ /--END CERTIFICATE--/ ) {

			$pem .= $line;

			if ( $line =~ /--END CERTIFICATE--/ ) {
				#say "|$pem|";
				my $cert = NSS::Certificate->new_from_pem($pem);
				$pem = "";
				add_trusted_cert_to_db($cert, $cert->subject);
			}
		}
	}

	close($fh);
}

sub import {
	my $pkg = shift; # us
        my @syms = (); # symbols to import. really should be empty
        my @dbpath = (); 

        my $dest = \@syms;

        for (@_) {
                if ( $_ eq ':dbpath') {
                        # switch to dbpath 
                        $dest = \@dbpath;
                        next;           
                }
                push (@$dest, $_);
        }
        
        die ("We do not export symbols") unless (scalar @syms == 0);	

	if ( scalar @dbpath == 0 ) {
		_init_nodb();
	} elsif (scalar @dbpath == 1) {
		_init_db($dbpath[0]);
	} else {
		die("More than one database path specified");
	}
}

END {
  __PACKAGE__->__cleanup;
}

package NSS::CertList;

sub new_from_rootlist {
	my ($class, $filename) = @_;

	my $certlist = NSS::CertList->new();

	my $pem;

	open (my $fh, "<", $filename);
	while ( my $line = <$fh> ) {
		if ( $line =~ /--BEGIN CERTIFICATE--/ .. $line =~ /--END CERTIFICATE--/ ) {

			$pem .= $line;

			if ( $line =~ /--END CERTIFICATE--/ ) {
				#say "|$pem|";
				my $cert = NSS::Certificate->new_from_pem($pem);
				$pem = "";
				$certlist->add($cert);
			}
		}
	}

	close($fh);

	return $certlist;
}

package NSS::Certificate;
use MIME::Base64 ();

sub serial {
	return unpack("H*", serial_raw(@_));
}

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


1;

__END__

=head1 NAME

NSS - Perl interface for the certificate handling parts of the NSS api.

=head1 SYNOPSIS

  use NSS;

  my $cert = NSS::Certificate->new($der);

  print $x509->subject() . "\n";
  print $x509->issuer() . "\n";

  my $valid = $cert->validate();


=head1 ABSTRACT

  NSS - Perl interface for the certificate handling parts of the NSS api..

=head1 DESCRIPTION

=head2 EXPORT

None.

=head1 FUNCTIONS

=head1 SEE ALSO

OpenSSL(1), Crypt::X509

=head1 AUTHOR

Bernhard Amann, E<lt>bernhard@icsi.berkeley.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2012 by Bernhard Amann

This library is free software and licensed under the GNU LGPL, version 2.1
as available at http://www.gnu.org/licenses/lgpl-2.1.html.

The library contains source code of the Mozilla Network Security Services; for
NSS license information please see http://www.mozilla.org/projects/security/pki/nss/.

=cut
