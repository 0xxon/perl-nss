use 5.10.1;
use strict;
use warnings;

use Test::More tests=>27;

BEGIN { use_ok( 'NSS' ); }

{
	my $pem = slurp("certs/selfsigned.crt");
	my $cert = NSS::Certificate->new_from_pem($pem);

	isa_ok($cert, 'NSS::Certificate');
	is($cert->issuer, 'E=email@domain.invalid,CN=Test Certificate,OU=Test Unit,L=Berkeley,ST=California,C=US', 'issuer');
	is($cert->subject, 'E=email@domain.invalid,CN=Test Certificate,OU=Test Unit,L=Berkeley,ST=California,C=US', 'subject');
	ok($cert->version == 1, 'version == 1');
	is($cert->serial, '009863c9c6d7bd0ee5', 'serial');
	is($cert->notBefore, 'Mon Oct 15 22:23:31 2012', 'notBefore');
	is($cert->notAfter, 'Tue Oct 15 22:23:31 2013', 'notAfter');
	ok(!$cert->subj_alt_name, 'no alt name');
	is($cert->common_name, "Test Certificate", 'Test Certificate');
	is($cert->sig_alg_name, "SHA1WithRSA", 'SHA1WithRSA');
	is($cert->key_alg_name, "RSAEncr", 'RSAEncr');
	ok($cert->bit_length == 1024, 'bit_length == 1024');
	ok($cert->is_root, 'selfsigned');
}

{
	my $pem = slurp("certs/google.crt");
	my $cert = NSS::Certificate->new_from_pem($pem);

	isa_ok($cert, 'NSS::Certificate');
	is($cert->issuer, 'CN=Thawte SGC CA,O=Thawte Consulting (Pty) Ltd.,C=ZA', 'issuer');
	is($cert->subject, 'CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US', 'subject');
	ok($cert->version == 3, 'version == 3');
	is($cert->serial, '4f9d96d966b0992b54c2957cb4157d4d', 'serial');
	is($cert->notBefore, 'Wed Oct 26 00:00:00 2011', 'notBefore');
	is($cert->notAfter, 'Mon Sep 30 23:59:59 2013', 'notAfter');
	ok(!$cert->subj_alt_name, 'no alt name');
	is($cert->common_name, "www.google.com", 'Test Certificate');
	is($cert->sig_alg_name, "SHA1WithRSA", 'SHA1WithRSA');
	is($cert->key_alg_name, "RSAEncr", 'RSAEncr');
	ok($cert->bit_length == 1024, 'bit_length == 1024');
	ok(!$cert->is_root, 'not selfsigned');
}



sub slurp {
  local $/=undef;
  open (my $file, shift) or die "Couldn't open file: $!";
  my $string = <$file>;
  close $file;
  return $string;
}
