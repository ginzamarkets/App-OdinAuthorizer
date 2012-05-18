#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'App::OdinAuthorizer' ) || print "Bail out!\n";
}

diag( "Testing App::OdinAuthorizer $App::OdinAuthorizer::VERSION, Perl $], $^X" );
