# Note: this file has been initially generated by Module::Build::Convert 0.49

use strict;
use warnings;

use Module::Build;

my $build = Module::Build->new(
    module_name => 'App::OdinAuthorizer',
    dist_abstract => 'Autorizer webapp for Apache2::Authen::OdinAuth',
    dist_author => 'q{Maciej Pasternacki <maciej@pasternacki.net>}',
    dist_version_from => 'lib/App/OdinAuthorizer.pm',
    requires => {
        'Dancer' => '1.3095',
        'Test::More' => 0,
        'YAML' => 0,

        'Clone' => 0,    # https://github.com/sukria/Dancer/issues/253
        'LWP::Protocol::https' => 0,
        'Net::SSLeay' => 0,
        'Net::Google::FederatedLogin' => 0,
        'Apache2::Authen::OdinAuth' => 0,
        'Plack' => 0,
        'Template' => 0,
    },
    build_requires => {
        'Test::More' => 0,
    },
    add_to_cleanup => [
        'App-OdinAuthorizer-*',
    ],
    license => 'unknown',
    create_readme => 1,
    create_makefile_pl => 'traditional',
    );

$build->create_build_script;
