use inc::Module::Install;

name('Crypt-NSS');
license('lgpl');
perl_version('5.10.1');
all_from('NSS.pm');

#homepage '';
#bugtracker '';

requires_external_cc();

cc_inc_paths('/opt/local/include', '/opt/local/include/nss', '/opt/local/include/nspr', '/home/bernhard/nss/include', '/home/bernhard/nss/include/nss' );

libs [ '-L/opt/local/lib/nspr', '-L/home/bernhard/nss/lib -L/opt/local/lib/nss -lnss3' ];

cc_optimize_flags('-O2 -g -Wall -Werror -std=c99');

auto_install();
WriteAll();
