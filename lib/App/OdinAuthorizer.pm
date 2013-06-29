package App::OdinAuthorizer;
use Dancer ':syntax';

use Crypt::OdinAuth;
use Net::Google::FederatedLogin;
use URI::Escape;
use URI;

our $VERSION = '0.2';

sub odin_authorize {
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
    expires => $options{'expires'},
    http_only => 1,
    secure => !!$options{'secure'});
}

sub odin_deauthorize {
  cookie( setting('odin-auth')->{'cookie'} => '',
          domain => setting('odin-auth')->{'domain'},
          path => '/',
          expires => 0 );
}

sub return_to {
  my $return_to = uri_for('/oid');
  if ( params->{'ref'} ) {
    my $ref = URI->new(params->{'ref'})->host;
    my $cookie_domain = setting('odin-auth')->{'domain'};
    $ref =~ /\Q$cookie_domain\E$/
      or die "Ref domain $ref not in $cookie_domain\n";
    $return_to->query('ref=' . params->{'ref'});
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
  my $fl = Net::Google::FederatedLogin->new(
    cgi => request,
    return_to => return_to);

  eval { $fl->verify_auth; } or die "Unauthorized ($@)\n";

  $fl->get_extension('http://openid.net/srv/ax/1.0')->get_parameter('value.email') =~ /^([-_.\w]+)\@$domain$/
    or die "Wrong email domain\n";

  return $1;
}

get '/oid' => sub {
  my $username;

  if ( params->{'openid.ns'} ) {
    eval { $username = verify_openid_response; };
    if ( !$@ ) {
      odin_authorize(username => $username);
      # FIXME: use flash message in session to indicate that
      # user has just logged in.
      redirect( params->{'ref'} || '/' );
    } else {
      template('denied', { reason => $@, try_again_url => '/' });
    }
  }
};

get '/' => sub {
  if ( my $cookie = cookie(setting('odin-auth')->{'cookie'}) ) {
    my ( $user, $roles );
    eval { ( $user, $roles ) =
             Crypt::OdinAuth::check_cookie(
               setting('odin-auth')->{'secret'},
               $cookie,
               request->header('User-Agent')); };
    if ( !$@ ) {
      odin_authorize(username => $user);
      template('index', { %{setting('template-variables') || {}},
                          username => $user });
    } else {
      odin_deauthorize;
      template('unauthed', { auth_url => get_auth_url, error => $@ });
    }
  } else {
    template('unauthed', { auth_url => get_auth_url });
  }
};

get '/logout' => sub {
  odin_deauthorize;
  redirect '/';
};

true;
