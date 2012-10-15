use inc::Module::Install;

name('Crypt-NSS');
license('lgpl');
perl_version('5.10.1');
all_from('NSS.pm');

#homepage '';
#bugtracker '';

requires_external_cc();

cc_inc_paths('/opt/local/include', '/opt/local/include/nss', '/opt/local/include/nspr' );

libs [ '-L/opt/local/lib/nspr', '-L/opt/local/lib/nss -lnss3' ];

cc_optimize_flags('-O2 -g -Wall -Werror');

auto_install();
WriteAll();
