# -*- coding: utf-8 -*-

"""Form and cookie based authentication middleware

As with all the other AuthKit middleware, this middleware is described in
detail in the AuthKit manual and should be used via the
``authkit.authenticate.middleware`` function.

The option form.status can be set to "200 OK" if the Pylons error document
middleware is intercepting the 401 response and just showing the standard 401
error document. This will not happen in recent versions of Pylons (0.9.6)
because the multi middleware sets the environ['pylons.error_call'] key so that
the error documents middleware doesn't intercept the response.

From AuthKit 0.4.1 using 200 OK when the form is shown is now the default. 
This is so that Safari 3 Beta displays the page rather than trying to 
handle the response itself as a basic or digest authentication.
"""

from paste.auth.form import AuthFormHandler
from paste.request import parse_formvars
from authkit.authenticate import get_template, valid_password, \
   get_authenticate_function, strip_base, RequireEnvironKey, \
   AuthKitAuthHandler
from authkit.authenticate.multi import MultiHandler, status_checker

import inspect
import logging
import urllib
log = logging.getLogger('authkit.authenticate.form')

def user_data(state):
    return 'User data string'

def template(method=False):
    t = """\
<html>
  <head><title>Please Sign In</title></head>
  <body>
    <h1>Please Sign In</h1>
    <form action="%s" method="post">
      <dl>
        <dt>Username:</dt>
        <dd><input type="text" name="username"></dd>
        <dt>Password:</dt>
        <dd><input type="password" name="password"></dd>
      </dl>
      <input type="submit" name="authform" value="Sign In" />
    </form>
  </body>
</html>
"""
    if method is not False:
        t = t.replace('post', method)
    return t

class AttributeDict(dict):
    def __getattr__(self, name):
        if not self.has_key(name):
            raise AttributeError('No such attribute %r'%name)
        return self.__getitem__(name)

    def __setattr__(self, name, value):
        raise NotImplementedError(
            'You cannot set attributes of this object directly'
        )

class FormAuthHandler(AuthKitAuthHandler, AuthFormHandler):
    def __init__(
        self, 
        app,
        charset=None,
        status="200 OK",
        method='post',
        action=None,
        user_data=None,
        **p
    ):
        AuthFormHandler.__init__(self, app, **p)
        self.status = status
        self.content_type = 'text/html'
        self.charset = charset
        if self.charset is not None:
            self.content_type = self.content_type + '; charset='+charset
        self.method = method
        self.action = action
        self.user_data = user_data
    
    def on_authorized(self, environ, start_response):
        if self.user_data is not None:
            state = environ.get('wsgiorg.state')
            if not state:
                environ['wsgiorg.state'] = state = AttributeDict()
                state['environ'] = environ
                state['start_response'] = start_response
            environ['paste.auth_tkt.set_user'](userid=environ['REMOTE_USER'], user_data=self.user_data(state))
        else:
            environ['paste.auth_tkt.set_user'](userid=environ['REMOTE_USER'])
        return self.application(environ, start_response)
        
    def __call__(self, environ, start_response):
        # Shouldn't ever allow a response if this is called via the 
        # multi handler
        username = environ.get('REMOTE_USER','')
        formvars = parse_formvars(environ, include_get_vars=True)
        username = formvars.get('username')
        password = formvars.get('password')
        if username and password:
            if self.authfunc(environ, username, password):
                log.debug("Username and password authenticated successfully")
                environ['AUTH_TYPE'] = 'form'
                environ['REMOTE_USER'] = username
                environ['REQUEST_METHOD'] = 'GET'
                environ['CONTENT_LENGTH'] = ''
                environ['CONTENT_TYPE'] = ''
                del environ['paste.parsed_formvars']
                return self.on_authorized(environ, start_response)
            else:
                log.debug("Username and password authentication failed")
        else:
            log.debug("Either username or password missing")
        action = self.action or construct_url(environ)
        log.debug("Form action is: %s", action)

        # Inspect the function to see if we can pass it anything useful:
        args = {}
        kargs = {'environ':environ}
        if environ.has_key('gi.state'):
            kargs['state'] = environ['gi.state']
        for name in inspect.getargspec(self.template)[0]:
            if kargs.has_key(name):
                args[name] = kargs[name]
        if self.method != 'post':
            args['method'] = self.method
        content = self.template(**args) % (action)
        if self.charset is not None:
            content = content.encode(self.charset)
            
        writable = start_response(
            self.status,
            [
                ('Content-Type', self.content_type),
                ('Content-Length', str(len(content))),
                # Added for IE compatibility - see #54
                ('Pragma', 'no-cache'),
                ('Cache-Control', 'no-cache'),
            ]
        )
        return [content]

def construct_url(environ, with_query_string=True, with_path_info=True,
                  script_name=None, path_info=None, querystring=None):
    """Reconstructs the URL from the WSGI environment.

    You may override SCRIPT_NAME, PATH_INFO, and QUERYSTRING with
    the keyword arguments.

    """
    url = '://'
    host = environ.get('HTTP_X_FORWARDED_HOST', environ.get('HTTP_HOST'))
    port = None
    if ':' in host:
        host, port = host.split(':', 1)
    else:
        # See if the request is proxied
        host = environ.get('HTTP_X_FORWARDED_HOST', environ.get('HTTP_X_FORWARDED_FOR'))
        if host is not None:
            # Request was proxied, get the correct data
            host = environ.get('HTTP_X_FORWARDED_HOST')
            port = environ.get('HTTP_X_FORWARDED_PORT')
            if port is None and environ.get('HTTP_X_FORWARDED_SSL') == 'on':
                port = '443'
            if not port:
                log.warning(
                    'No HTTP_X_FORWARDED_PORT or HTTP_X_FORWARDED_SSL found '
                    'in environment, cannot '
                    'determine the correct port for the form action. '
                ) 
            if not host:
                log.warning(
                    'No HTTP_X_FORWARDED_HOST found in environment, cannot '
                    'determine the correct hostname for the form action. ' 
                    'Using the value of HTTP_HOST instead.'
                )   
                host = environ.get('HTTP_HOST')
        else:
            # Request was not proxied
            if environ['wsgi.url_scheme'] == 'https':
                port = 443
            if host is None:
                host = environ.get('HTTP_HOST')
            if port is None:
                port = environ.get('SERVER_PORT')
    url += host
    if port:
        if str(port) == '443':
            url = 'https'+url
        elif str(port) == '80':
            url = 'http'+url
        else:
            # Assume we are running HTTP on a non-standard port
            url = 'http'+url+':%s' % port
    else:
        url = 'http'+url
    if script_name is None:
        url += urllib.quote(environ.get('SCRIPT_NAME',''))
    else:
        url += urllib.quote(script_name)
    if with_path_info:
        if path_info is None:
            url += urllib.quote(environ.get('PATH_INFO',''))
        else:
            url += urllib.quote(path_info)
    if with_query_string:
        if querystring is None:
            if environ.get('QUERY_STRING'):
                url += '?' + environ['QUERY_STRING']
        elif querystring:
            url += '?' + querystring
    return url

def load_form_config(
    app, 
    auth_conf, 
    app_conf=None,
    global_conf=None,
    prefix='authkit.method.form',
):
    app = RequireEnvironKey(
        app,
        'paste.auth_tkt.set_user',
        missing_error=(
            'Missing the key %(key)s from the environ. '
            'Have you added the cookie method after the form method?'
        )
    )
    template_conf = strip_base(auth_conf, 'template.')
    if template_conf:
        template_ = get_template(template_conf, prefix=prefix+'template.')
    else:
        template_ = template
    authenticate_conf = strip_base(auth_conf, 'authenticate.')
    app, authfunc, users = get_authenticate_function(
        app, 
        authenticate_conf, 
        prefix=prefix+'authenticate.', 
        format='basic'
    )
    charset = auth_conf.get('charset')
    method = auth_conf.get('method', 'post')
    action = auth_conf.get('action')
    user_data = auth_conf.get('userdata')
    if method.lower() not in ['get','post']:
        raise Exception('Form method should be GET or POST, not %s'%method)
    return app, {
        'authfunc': authfunc, 
        'template': template_, 
        'charset': charset, 
        'method': method,
        'action': action,
        'user_data': user_data or None,
    }, None

def make_form_handler(
    app, 
    auth_conf, 
    app_conf=None,
    global_conf=None,
    prefix='authkit.method.form', 
):
    app, auth_handler_params, user_setter_params = load_form_config(
        app, 
        auth_conf, 
        app_conf=None,
        global_conf=None,
        prefix='authkit.method.form',
    )
    app = MultiHandler(app)
    app.add_method(
        'form', 
        FormAuthHandler, 
        authfunc=auth_handler_params['authfunc'], 
        template=auth_handler_params['template'], 
        charset=auth_handler_params['charset'],
        method=auth_handler_params['method'],
        action=auth_handler_params['action'],
        user_data=auth_handler_params['user_data'],
    )
    app.add_checker('form', status_checker)
    return app

# Backwards compatbility
Form = FormAuthHandler

