# -*- coding: utf-8 -*-

"""\
This is an example of multiple middleware components being setup at once in
such away that the authentication method used is dynamically selected at
runtime. What happens is that each authentication method is based an
``AuthSwitcher`` object which when a status response matching a code specified
in ``authkit.setup.intercept`` is intercepted, will perform a ``switch()``
check. If the check returns ``True`` then that particular ``AuthHandler`` will
be triggered. 

In this example the ``AuthSwitcher`` decides whether to trigger a particular
``AuthHandler`` based on the value of the ``authkit.authhandler`` key in
``environ`` and this is set when visiting the various paths such as
``/private_openid``, ``private_basic`` etc. Notice though that the form method
is setup with a ``Default`` ``AuthSwitcher`` whose ``switch()`` method always
returns ``True``. This means of the other ``AuthHandlers`` don't handle the
response, the from method's handler will. This is the case if you visit
``/private``.

Once the user is authenticated the ``UserSetter``s middleware sets the
``REMOTE_USER`` environ variable so that the user remains signed in. This means
that a user can authenticate with say digest authentication and when they visit
``/private_openid`` they will still be signed in, even if that wasn't the
method they used to authenticate.

Also, note that you are free to implement and use any ``AuthSwitcher`` you like
as long as it derives from ``AuthSwitcher`` so you could for example choose
which authentication method to show to the user based on their IP address.

The authentication details for each method in this example are:

Form: username2:password2 
Digest: test:test (or any username which is identical to the password)
Basic: test:test (or any username which is identical to the password)
OpenID: any valid openid (get one at myopenid.com for example)

Of course, everything is totally configurable.
"""

# Needed for the middleware
from authkit.authenticate import middleware, strip_base
from authkit.authenticate.open_id import OpenIDAuthHandler, \
    OpenIDUserSetter, load_openid_config
from authkit.authenticate.form import FormAuthHandler, load_form_config
from authkit.authenticate.cookie import CookieUserSetter, load_cookie_config
from authkit.authenticate.basic import BasicAuthHandler, BasicUserSetter, \
    load_basic_config
from authkit.authenticate.digest import DigestAuthHandler, \
    DigestUserSetter, load_digest_config, digest_password
from authkit.authenticate.multi import MultiHandler, AuthSwitcher, \
    status_checker

# Needed for the sample app
from authkit.authorize import authorize_request
from authkit.permissions import RemoteUser, no_authkit_users_in_environ, \
    AuthKitConfigError

# Setup a switcher which will switch if environ['authkit.authhandler'] equals
# the method name specified and if the response matches one of the values of
# authkit.setup.intercept

class EnvironKeyAuthSwitcher(AuthSwitcher):
    def __init__(self, method, key='authkit.authhandler'):
        self.method = method
        self.key = key

    def switch(self, environ, status, headers):
        if environ.has_key(self.key) and environ[self.key] == self.method:
            return True
        return False

class Default(AuthSwitcher):
    def switch(self, environ, status, headers):
        return True

def make_multi_middleware(app, auth_conf, app_conf=None, global_conf=None, 
    prefix='authkit.'):

    # Load the configurations and any associated middleware
    app, oid_auth_params, oid_user_params = load_openid_config(
        app, strip_base(auth_conf, 'openid.'))
    app, form_auth_params, form_user_params = load_form_config(
        app, strip_base(auth_conf, 'form.'))
    app, cookie_auth_params, cookie_user_params = load_cookie_config(
        app, strip_base(auth_conf, 'cookie.'))
    app, basic_auth_params, basic_user_params = load_basic_config(
        app, strip_base(auth_conf, 'basic.'))
    app, digest_auth_params, digest_user_params = load_digest_config(
        app, strip_base(auth_conf, 'digest.'))

    # The cookie plugin doesn't provide an AuthHandler so no config
    assert cookie_auth_params == None
    # The form plugin doesn't provide a UserSetter (it uses cookie)
    assert form_user_params == None

    # Setup the MultiHandler to switch between authentication methods
    # based on the value of environ['authkit.authhandler'] if a 401 is 
    # raised
    app = MultiHandler(app)
    app.add_method('openid', OpenIDAuthHandler, **oid_auth_params)
    app.add_checker('openid', EnvironKeyAuthSwitcher('openid'))
    app.add_method('basic', BasicAuthHandler, **basic_auth_params)
    app.add_checker('basic', EnvironKeyAuthSwitcher('basic'))
    app.add_method('digest', DigestAuthHandler, **digest_auth_params)
    app.add_checker('digest', EnvironKeyAuthSwitcher('digest'))
    app.add_method('form', FormAuthHandler, **form_auth_params)
    app.add_checker('form', Default())

    # Add the user setters to set REMOTE_USER on each request once the
    # user is signed on.
    app = DigestUserSetter(app, **digest_user_params)
    app = BasicUserSetter(app, **basic_user_params)
    # OpenID relies on cookie so needs to be set up first
    app = OpenIDUserSetter(app, **oid_user_params)
    app = CookieUserSetter(app, **cookie_user_params)

    return app

def sample_app(environ, start_response):
    """
    A sample WSGI application that returns a 401 status code when the path 
    ``/private`` is entered, triggering the authenticate middleware to 
    prompt the user to sign in.
    
    If used with the authenticate middleware's form method, the path 
    ``/signout`` will display a signed out message if 
    ``authkit.cookie.signout = /signout`` is specified in the config file.
    
    If used with the authenticate middleware's forward method, the path 
    ``/signin`` should be used to display the sign in form.
    
    The path ``/`` always displays the environment.
    """
    if environ['PATH_INFO']=='/private':
        authorize_request(environ, RemoteUser())
    if environ['PATH_INFO']=='/private_openid':
        environ['authkit.authhandler'] = 'openid'
        authorize_request(environ, RemoteUser())
    if environ['PATH_INFO']=='/private_digest':
        environ['authkit.authhandler'] = 'digest'
        authorize_request(environ, RemoteUser())
    if environ['PATH_INFO']=='/private_basic':
        environ['authkit.authhandler'] = 'basic'
        authorize_request(environ, RemoteUser())
    if environ['PATH_INFO'] == '/signout':
        start_response(
            '200 OK', 
            [('Content-type', 'text/plain; charset=UTF-8')]
        )
        if environ.has_key('REMOTE_USER'):
            return ["Signed Out"]
        else:
            return ["Not signed in"]
    elif environ['PATH_INFO'] == '/signin':
        start_response(
            '200 OK', 
            [('Content-type', 'text/plain; charset=UTF-8')]
        )
        return ["Your application would display a \nsign in form here."]
    else:
        start_response(
            '200 OK', 
            [('Content-type', 'text/plain; charset=UTF-8')]
        )
    result = [
        'You Have Access To This Page.\n\nHere is the environment...\n\n'
    ]
    for k,v in environ.items():
        result.append('%s: %s\n'%(k,v))
    return result

def digest_authenticate(environ, realm, username):
    password = username
    return digest_password(realm, username, password)

def basic_authenticate(environ, username, password):
    return username == password

app = middleware(
    sample_app, 
    middleware = make_multi_middleware, 
    openid_path_signedin='/private',
    openid_store_type='file',
    openid_store_config='',
    openid_charset='UTF-8',
    cookie_secret='secret encryption string',
    cookie_signoutpath = '/signout',
    openid_sreg_required = 'fullname,nickname,city,country',
    openid_sreg_optional = 'timezone,email',
    openid_sreg_policyurl =  'http://localhost:5000',
    form_authenticate_user_data = """
        username2:password2
    """,
    form_charset='UTF-8',
    digest_realm='Test Realm',
    digest_authenticate_function=digest_authenticate,
    basic_realm='Test Realm', 
    basic_authenticate_function=basic_authenticate,
)

# XXX No Session variables in the config now.

if __name__ == '__main__':
    from paste.httpserver import serve
    serve(app, host='0.0.0.0', port=8080)

