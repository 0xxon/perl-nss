use inc::Module::Install;

name('Crypt-NSS-X509');
license('mozilla');
perl_version('5.10.1');
all_from('X509.pm');

homepage 'https://github.com/0xxon/perl-nss';
bugtracker 'https://github.com/0xxon/perl-nss/issues';

requires_external_cc();

cc_inc_paths('/opt/local/include', '/opt/local/include/nss', '/opt/local/include/nspr', '/home/johanna/nss/include', '/home/johanna/nss/include/nss' );

libs [ '-L/opt/local/lib/nspr', '-L/home/johanna/nss/lib -L/opt/local/lib/nss -lnss3' ];

cc_optimize_flags('-O2 -g -Wall -std=c99');

auto_install();
WriteAll();
