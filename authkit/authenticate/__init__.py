"""Authentication middleware

This module provides one piece of middleware named 
``authkit.authenticate.middleware`` which is used to intercept responses with
a specified status code, present a user with a means of authenticating 
themselves and handle the sign in process.

Each of the authentication methods supported by the middleware is described in
detail in the main AuthKit manual. The methods include:

* HTTP Basic (``basic``)
* HTTP Digest (``digest``)
* OpenID Passurl (``openid``)
* Form and Cookie (``form``)
* Forward (``forward``)
* Redirect (``redirect``)

The authenticate middleware can be configured directly or by means of a Paste
deploy config file as used by Pylons. It can be used directly like this:

.. code-block:: Python

    from authkit.authenticate import middleware, test_app
    from paste.httpserver import serve

    import sys
    app = middleware(
        test_app,
        enable = True,
        method = 'passurl',
        cookie_secret='some_secret',
    )
    
    serve(app, host='0.0.0.0', port=8000)

"""

import types
import warnings
import logging
import os
import os.path

from paste.util.import_string import eval_import
from .multi import MultiHandler, status_checker
from pkg_resources import iter_entry_points, load_entry_point
from paste.deploy.converters import asbool

import paste.httpexceptions
import webob.exc

from authkit.authorize import authorize_request
from authkit.permissions import RemoteUser, no_authkit_users_in_environ, \
    AuthKitConfigError

# Main middleware base classes

class AuthKitAuthHandler(object):
    """
    The base class for all middleware responsible for handling 
    authentication and setting whatever needs to be set so that the
    ``AuthKitUserSetter`` middleware can set REMOTE_USER on subsequent
    requests. ``AuthKitAuthHandler``s only get inserted into the 
    middleware stack if an appropriate status code (as set in the 
    ``authkit.setup.intercept`` config option) is intercepted by the 
    authentication middleware.
    """
    pass

class AuthKitUserSetter(object):
    """
    The base class for all middleware responsible for attempting to set
    REMOTE_USER on each request. The class is overridden by the induvidual
    handlers.
    """
    pass

# Setting up logging

log = logging.getLogger('authkit.authenticate')
    
def strip_base(conf, base):
    result = {}
    for key in list(conf.keys()):
        if key.startswith(base):
            result[key[len(base):]] = conf[key]
    return result

def swap_underscore(*confs):
    results = []
    for conf in confs:
        result = {}
        for k,v in list(conf.items()):
            result[k.replace('.','_')] = v
        results.append(result)
    return results

def valid_password(environ, username, password): 
    """ 
    A function which can be used with the ``basic`` and ``form`` authentication
    methods to validate a username and passowrd.

    This implementation is used by default if no other method is specified. It
    checks the for an ``authkit.users`` object present in the ``environ``
    dictionary under the ``authkit.users`` key and uses the information there
    to validate the username and password.

    In this implementation usernames are case insensitive and passwords are
    case sensitive. The function returns ``True`` if the user ``username`` has
    the password specified by ``password`` and returns ``False`` if the user
    doesn't exist or the password is incorrect.

    If you create and specify your own ``authkit.users`` object with the same
    API, this method will also work correctly with your custom solution. See
    the AuthKit manual for information on the user management api, how to
    specify a different ``authkit.users`` object (say to read user information
    from a file rather than have it specified directly) and for information on
    how to create your own ``Users`` objects.
    """
    log.debug("valid_password called. username: %s", username)
    if 'authkit.users' not in environ:
        raise no_authkit_users_in_environ
    users = environ['authkit.users']
    if not users.user_exists(username):
        return False
    elif users.user_has_password(username.lower(), password):
        return True
    return False


def digest_password(environ, realm, username):
    """
    This is similar to ``valid_password()`` but is used with the ``digest``
    authentication method and rather than checking a username and password and
    returning ``True`` or ``False`` it takes the realm and username as input,
    looks up the correct password and and returns a digest by calling the
    ``authkit.authenticate.digest.digest_password()`` function with the
    parameters ``realm``, ``username`` and ``password`` respectively. The
    digest returned is then compared with the one submitted by the browser.

    As with ``valid_password()`` this method is designed to work with the user
    management API so you can use it with ``authkit.users`` objects or your own
    custom ``Users`` objects. Alternatively you can specify your own function
    which can lookup the password in whichever way you prefer, perhaps from a
    database or LDAP connection.
    
    Only required if you intend to use HTTP digest authentication.
    """
    log.debug(
        "digest_password called. username: %s, realm: %s", username, realm
    )
    if 'authkit.users' not in environ:
        raise no_authkit_users_in_environ
    users = environ['authkit.users']
    if users.user_exists(username):
        password = users.user(username)['password']
        return digest.digest_password(realm, username, password)
    # After speaking to Clark Evans who wrote the origianl code, this is the 
    # correct thing:
    return None

class AddUsersObjectToEnviron(object):
    """Simple middleware which adds a Users object to the environ."""
    def __init__(self, app, key, value, *k, **p):
        self.app = app
        self.k = k
        self.p = p
        self.key = key
        self.value = value

    def __call__(self, environ, start_response):
        p = {}
        p.update(self.p)
        p['environ'] = environ
        environ[self.key] = self.value(*self.k, **p)
        return self.app(environ, start_response)

def get_authenticate_function(app, authenticate_conf, format, prefix):
    """
    Sets up the users object, adds the middleware to add the users object
    to the environ and then returns authenticate methods to check a password
    and a digest.
    """
    function = None
    users = None
    if len(authenticate_conf) < 1:
        raise AuthKitConfigError('Expected at least one authenticate key, not'
                                 ' %r'%authenticate_conf)
    if list(authenticate_conf.keys()) == ['function']:
        function = authenticate_conf['function']
        if isinstance(function, str):
            function = eval_import(function)
    else:
        user_conf = strip_base(authenticate_conf, 'user.')
        if not user_conf:
            raise AuthKitConfigError('No authenticate function or users specified')
        else:
            if 'encrypt' in user_conf:
                if format == 'digest':
                    raise AuthKitConfigError('Encryption cannot be used with '
                        'digest authentication because the server needs to '
                        'know the password to generate the digest, try basic '
                        'or form and cookie authentication instead')
                enc_func = eval_import(user_conf['encrypt'])
                secret = user_conf.get('encrypt.secret','')
                def encrypt(password):
                    return enc_func(password, secret)
            else:
                encrypt = None
            user_object = 'authkit.users.UsersFromString'
            if 'type' in list(user_conf.keys()):
                user_object = user_conf['type']
            if isinstance(user_object, str):
                user_object = eval_import(user_object)

            if not hasattr(user_object, "api_version"):
                users = user_object(user_conf['data'], encrypt)
                app = AddToEnviron(app, 'authkit.users', users)
                log.debug("authkit.users added to environ")
            elif user_object.api_version == 0.4:
                app = AddUsersObjectToEnviron(
                    app, 
                    'authkit.users', 
                    user_object, 
                    encrypt=encrypt, 
                    data=user_conf.get('data'),
                )
                log.debug("Setting up authkit.users middleware")
            else:
                raise Exception(
                    'Unknown API version %s for user management API'%(
                        users.api_version,
                    )
                )         
            if format == 'basic':
                function = valid_password
                log.debug("valid_password chosen %r", function)
            elif format == 'digest':
                log.debug("digest_password chosen %r", function)
                function = digest_password
            else:
                raise Exception('Invalid format for authenticate function %r' 
                                % format)
    return app, function, users

def get_template(template_conf, prefix):
    """
    Another utility method to reduce code duplication. This function parses a
    template from one of the available template options:

    ``string``
        The template as a string
        
    ``file``
        A file containing the template

    ``obj``
        A paste eval_import string or callable which returns a string

    authkit.form.template.string = 
    authkit.form.template.file = 
    authkit.form.template.obj =

    """
    template = None
    if len(template_conf) != 1:
        raise AuthKitConfigError('Expected one template entry, not %r' % 
                                 (', '.join(list(template_conf.keys()))))
    if list(template_conf.keys())[0] not in ['string', 'file', 'obj']:
        raise AuthKitConfigError("Template option can only be 'string', 'file'"
                                 " or 'obj'")
    if list(template_conf.keys())[0] == 'string':
        template = template_conf['string']
    elif list(template_conf.keys())[0] == 'file':
        if not os.path.exists(template_conf['file']):
            raise AuthKitConfigError('No such file %r exists. It was specified'
                                     ' by config option %r' % 
                                     (template_conf['file'], prefix+'file'))
        fp = open(template_conf['file'], 'r')
        template = fp.read()
        fp.close()
        if not template:
            raise AuthKitConfigError('No data in template file %s specified by'
                                     ' config option %r' % 
                                     (template_conf['file'], prefix+'file'))
    elif list(template_conf.keys())[0] == 'obj':
        template = eval_import(template_conf['obj'])
        if not template:
            raise AuthKitConfigError('No data in template obj %s specified by '
                                     'config option %r' % 
                                     (template_conf['obj'], prefix+'obj'))
    else:
        raise AuthKitConfigError("Unknown option %r" % 
                                 (prefix+list(template_conf.keys())[0]))
    if not template:
        raise AuthKitConfigError("The template loaded did not contain any data")
    if isinstance(template, str):
        def render_template():
            return template
        return render_template
    return template
    
#
# Main middleware creator 
#

class AddToEnviron(object):
    """
    Simple middleware which adds a key to the ``environ`` dictionary.
    
    Used to add the ``authkit.users`` key to the environ when this is
    appropriate.
    """
    def __init__(self, app, key, object):
        self.app = app
        self.key = key
        self.object = object
        
    def __call__(self, environ, start_response):
        environ[self.key] = self.object
        return self.app(environ, start_response)

class AddDictToEnviron(object):
    """Simple middleware which adds the values of a dict to the environ."""
    def __init__(self, app, dct):
        self.app = app
        self.dct = dct
        
    def __call__(self, environ, start_response):
        environ.update(self.dct)
        return self.app(environ, start_response)

class RequireEnvironKey(object):
    def __init__(self, app, key, missing_error=None):
        self.app = app
        self.key = key
        self.missing_error = missing_error or \
            'Missing the key %(key)s from the environ. Have you setup the ' \
            'correct middleware?'
        
    def __call__(self, environ, start_response):
        if self.key not in environ:
            raise Exception(self.missing_error%{'key':self.key})
        return self.app(environ, start_response)

def get_methods():
    """Get a dictionary of the available method entry points."""
    available_methods = {}
    for method_handler in iter_entry_points(group='authkit.method', name=None):
        available_methods[method_handler.name] = method_handler
    return available_methods

def load_method(name, from_these=None):
    if from_these:
        return from_these[name].load()
    else:
        return load_entry_point('AuthKit','authkit.method',name)

def load_config(options, app_conf, prefix):
    merged = strip_base(app_conf, prefix)
    
    # Now override the auth_conf_options with the manaully specified options
    for key, value in list(options.items()):
        if key in merged:
            warnings.warn(
                'Key %s with value %r set in the config file is being ' + \
                'replaced with value %r set in the application'%(
                    key,
                    auth_conf_options[key],
                    value
                )   
            )
        merged[key.replace('_','.')] = value
    return merged

class HTTPExceptionHandler(object):
    """
    catches exceptions and turns them into proper HTTP responses

    Attributes:

       ``warning_level``
           This attribute determines for what exceptions a stack
           trace is kept for lower level reporting; by default, it
           only keeps stack trace for 5xx, HTTPServerError exceptions.
           To keep a stack trace for 4xx, HTTPClientError exceptions,
           set this to 400.

    This middleware catches any exceptions (which are subclasses of
    ``HTTPException``) and turns them into proper HTTP responses.
    Note if the headers have already been sent, the stack trace is
    always maintained as this indicates a programming error.

    Note that you must raise the exception before returning the
    app_iter, and you cannot use this with generator apps that don't
    raise an exception until after their app_iter is iterated over.
    
    .. note::
        
        This originally came from paste.httpexceptions.HTTPExceptionHandler
        and is patched with comments below for compatibility with 
        webob + Python 2.4
    
    """

    def __init__(self, application, warning_level=None):
        assert not warning_level or ( warning_level > 99 and
                                      warning_level < 600)
        self.warning_level = warning_level or 500
        self.application = application

    def __call__(self, environ, start_response):
                    
        # Note that catching the webob exception is for Python 2.4 support.
        # In the brave new world of new-style exceptions (derived from object)
        # multiple inheritance works like you'd expect: the NotAuthenticatedError 
        # is caught because it descends from the past and webob exceptions.
        # In the old world (2.4-), the webob exception needs to be in the catch list
            
        environ['paste.httpexceptions'] = self
        environ.setdefault('paste.expected_exceptions',
                           []).extend([paste.httpexceptions.HTTPException,
                                       webob.exc.HTTPException])
        try:
            return self.application(environ, start_response)        
        except (paste.httpexceptions.HTTPException, 
                webob.exc.HTTPException) as exc:        
            return exc(environ, start_response)

def middleware(app, app_conf=None, global_conf=None, prefix='authkit.', 
               handle_httpexception=True, middleware=None, **options):   
    """
    This function sets up the AuthKit authenticate middleware and its use and 
    options are described in detail in the AuthKit manual.
   
    The function takes the following arguments and returns a WSGI application 
    wrapped in the appropriate AuthKit authentication middleware based on the 
    options specified:

    ``app``
        The WSGI application the authenticate middleware should wrap

    ``app_conf``
        A paste deploy ``app_conf`` dictionary to be used to setup the 
        middleware

    ``global_conf``
         A paste deploy ``global_conf`` dictionary

    ``prefix``
        The prefix which all authkit related options in the config file will
        have prefixed to their names. This defaults to ``authkit.`` and
        shouldn't normally need overriding.

    ``middleware``
        A make_middleware function which should be called directly instead of 
        loading and calling a function based on the method name. If this is 
        set then ``authkit.setup.methof`` should not be set.
    
    ``**options``
        Any AuthKit options which are setup directly in Python code. If 
        specified, these options will override any options specifed in a config
        file.

    All option names specified in the config file will have their prefix
    removed and any ``.`` characters replaced by ``_`` before the options
    specified by ``options`` are merged in. This means that the the option
    ``authkit.cookie.name`` specified in a config file sets the same options as
    ``cookie_name`` specified directly as an option.
    """
    if handle_httpexception:
        app = HTTPExceptionHandler(app)
    
    # Configure the config files
    
    if global_conf is None:
        global_conf = {}
    if app_conf is None:
        app_conf = {}
    if not isinstance(app_conf, dict):
        raise AuthKitConfigError(
            "Expected app_conf to be paste deploy app_conf dictionary "
            "from not %r" % app_conf
        )
    
    # Merge config file and options
    available_methods = get_methods()
    
    all_conf = load_config(options, app_conf, prefix)
    if middleware is not None and 'setup.method' in all_conf:
        raise AuthKitConfigError(
            'You cannot specify a middleware function '
            'and an authkit.setup.method'
        )
    if not middleware and 'setup.method' not in all_conf:
        raise AuthKitConfigError('No authkit.setup.method was specified')

    # Add the configuration to the environment
    enable_ =  asbool(all_conf.get('setup.enable', True))
    all_conf['setup.enable'] = enable_
    app = AddToEnviron(app, 'authkit.config', all_conf)
    if 'setup.fakeuser' in all_conf:
        app = AddToEnviron(app, 'REMOTE_USER', all_conf['setup.fakeuser'])
 
    # Check to see if middleware is disabled
    if enable_ == False:
        warnings.warn("AuthKit middleware has been turned off by the config "
                      "option authkit.setup.enable")
        return app
    
    # Status Checking/Changing Middleware
    intercept = [str(x).strip() for x in \
                 all_conf.get('setup.intercept','401').split(',')]
    if not '401' in intercept:
        warnings.warn(
            "AuthKit is configured via the authkit.setup.intercept option not "
            "to intercept 401 responses so the authentication middleware will "
            "not be triggered even if a 401 Unauthenticated response is "
            "returned.")

    if middleware:
        prefix_ = prefix
        app = middleware(
            app,
            auth_conf=all_conf,
            app_conf=app_conf,
            global_conf=global_conf,
            prefix=prefix_,
        )
    else:
        methods = [method.strip() for method in all_conf['setup.method'].split(',')]
        log.debug("Trying to load the following methods: %r", methods)
        for method in methods:
            if method in ['setup','config']:
                raise AuthKitConfigError("The name %s is reserved cannot be used "
                                         "as a method name" % method)
            if method not in available_methods:
                raise AuthKitConfigError(
                    'The authkit method %r is not available. The available methods '
                    'are %s and %s'%(
                        all_conf['setup.method'],
                        ', '.join(list(available_methods.keys())[:-1]),
                        list(available_methods.keys())[-1],
                    )
                )
            prefix_ = prefix+method+'.'
            auth_conf = strip_base(all_conf, method+'.')
            
            app = available_methods[method].load()(
                app,
                auth_conf=auth_conf,
                app_conf=app_conf,
                global_conf=global_conf,
                prefix=prefix_,
            )
    app = AddDictToEnviron(
        app, 
        {
            'authkit.config':strip_base(all_conf, 'config.'),
            'authkit.intercept':intercept,
            'authkit.authenticate': True,
        }
    )
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
    if environ['PATH_INFO'] == '/signout':
        start_response('200 OK', [('Content-type', 'text/plain; charset=UTF-8')])
        if 'REMOTE_USER' in environ:
            return ["Signed Out"]
        else:
            return ["Not signed in"]
    elif environ['PATH_INFO'] == '/signin':
        start_response('200 OK', [('Content-type', 'text/plain; charset=UTF-8')])
        return ["Your application would display a \nsign in form here."]
    else:
        start_response('200 OK', [('Content-type', 'text/plain; charset=UTF-8')])
    result = ['You Have Access To This Page.\n\nHere is the environment...\n\n']
    for k,v in list(environ.items()):
        result.append('%s: %s\n'%(k,v))
    return result

