package NSS;

use strict;

use 5.10.1;

use vars qw($VERSION @EXPORT_OK);
use Exporter;
use base qw(Exporter);

use autodie qw(open close);
use Carp;

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
	shift if ( defined $_[0] && $_[0] eq __PACKAGE__ );
	my $filename = shift;

	carp("No rootlist filename provided") unless defined($filename);

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
	my $noinit = 0;

        my $dest = \@syms;

        for (@_) {
                if ( $_ eq ':dbpath') {
                        # switch to dbpath 
                        $dest = \@dbpath;
                        next;           
                } elsif ( $_ eq ':noinit' ) {
			$noinit = 1;
			next;
		}

                push (@$dest, $_);
        }
        
        die ("We do not export symbols") unless (scalar @syms == 0);	

	return if ( $noinit );

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
	my $class = shift;
	my $pem = shift;

	$pem =~ s/-----BEGIN CERTIFICATE-----// or die("Did not found certificate start");
	$pem =~ s/-----END CERTIFICATE-----// or die ("Did not found certificate end");

	my $der = MIME::Base64::decode($pem);
	if ( length($der) < 1 ) {
		die("Could not decode certificate");
	}

	return $class->new($der, @_);
}


1;

__END__

