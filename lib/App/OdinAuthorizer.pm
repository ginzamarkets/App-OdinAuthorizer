package App::OdinAuthorizer;
use Dancer ':syntax';

use CGI;
use Crypt::OdinAuth;
use Net::Google::FederatedLogin;
use URI::Escape;
use URI;

our $VERSION = '0.1';

sub god_authorize {
    my %args = @_;
    my %options = ( %{setting('odin-auth')}, %args );

    cookie(
        $options{'cookie'} => Crypt::OdinAuth::cookie_for(
            $options{'secret'},
            $options{'username'},
            $options{'roles'},
            request->user_agent,
        ),
        domain => $options{'domain'},
        path => '/',
        expires => $options{'expires'});
}

sub return_to {
    my $return_to = uri_for('/');
    if ( params->{'ref'} ) {
        my $ref = URI->new(params->{'ref'})->host;
        my $cookie_domain = setting('godauth')->{'domain'};
        $ref =~ /\Q$cookie_domain\E$/
            or die "Ref domain $ref not in $cookie_domain\n";
        $return_to->query('ref=' .  params->{'ref'});
    }
    return $return_to->as_string;
}

sub get_auth_url {
    my $domain = setting('google_apps_domain');
    my $fl = Net::Google::FederatedLogin->new(
        claimed_id => "https://www.google.com/accounts/o8/site-xrds?hd=$domain",
        return_to => return_to,
        extensions => [
            { ns          => 'ax',
              uri         => 'http://openid.net/srv/ax/1.0',
              attributes  => { mode     => 'fetch_request',
                               required => 'email',
                               type     => {
                                   email => 'http://axschema.org/contact/email'
                               }}}
        ]);
    return $fl->get_auth_url;
}

sub verify_openid_response {
    my $domain = setting('google_apps_domain');
    my $q = CGI->new();
    my $fl = Net::Google::FederatedLogin->new(  
        cgi => $q,
        return_to => return_to);

    eval { $fl->verify_auth; } or die "Unauthorized ($@)\n";

    $fl->get_extension('http://openid.net/srv/ax/1.0')->get_parameter('value.email') =~ /^([-_.\w]+)\@$domain$/
        or die "Wrong email domain\n";

    return $1;
}

sub process_openid_response {
    eval {
        my $username = verify_openid_response;
        god_authorize(username => $username);
        if ( params->{'ref'} ) {
            redirect params->{'ref'};
        } else {
            template('index', { username => $username });
        }
    } or template('denied', { reason => $@,
                              try_again_url => return_to });
}

get '/' => sub {
    if ( params->{'openid.ns'} ) {
        process_openid_response;
    } else {
        template('unauthed', { auth_url => get_auth_url });
    }
};


true;
