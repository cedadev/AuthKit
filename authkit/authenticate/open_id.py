"""Highly flexible OpenID based authentication middleware

.. Note::

    If you want to test this module feel free to setup an account at
    passurl.com. The site is in alpha and any accounts will be deleted before
    launch but it might help with testing.

Full documentation on the use of this OpenID module is in the AuthKit manual.

.. warning ::

    Any data returned from an OpenID identity provider is stored in the cookie
    user data. This is not encryted when sent to the browser (unless you are 
    using a secure connection). Whilst this is unlikely to be a major problem 
    in your application it is something to be aware of.

This middleware actually sets two cookies, one for AuthKit and one for a session
store to store the ID which OpenID information is keyed against.

The OpenID sreg variables you can use include:

``nickname``
    Any UTF-8 string that the End User wants to use as a nickname. 

``email``
    The email address of the End User as specified in section 3.4.1 of
    [RFC2822] (Resnick, P., "Internet Message Format," .). 

``fullname``
    UTF-8 string free text representation of the End User's full name. 

``dob``
    The End User's date of birth as YYYY-MM-DD. Any values whose representation
    uses fewer than the specified number of digits should be zero-padded. The
    length of this value MUST always be 10. If the End User user does not want
    to reveal any particular component of this value, it MUST be set to zero.
    For instance, if a End User wants to specify that his date of birth is in
    1980, but not the month or day, the value returned SHALL be "1980-00-00".

``gender``
    The End User's gender, "M" for male, "F" for female. 

``postcode``
    UTF-8 string free text that SHOULD conform to the End User's country's
    postal system. 

``country``
    The End User's country of residence as specified by ISO3166. 

``language``
    End User's preferred language as specified by ISO639. 

``timezone``
    ASCII string from TimeZone database
    For example, "Europe/Paris" or "America/Los_Angeles".
"""

import cgi
import paste.request
import string
import sys
from urlparse import urlparse # PJK 24/02/09 for updating referer session item
from authkit.authenticate import AuthKitConfigError
from paste.request import construct_url
from paste.util.import_string import eval_import
from openid.consumer import consumer
from openid.extensions import sreg
from openid.extensions import ax # PJK 19/08/08 added AX Extensions import
from openid.cryptutil import randomString
from authkit.authenticate import get_template, valid_password, \
   get_authenticate_function, strip_base, RequireEnvironKey, \
   AuthKitUserSetter, AuthKitAuthHandler
from authkit.authenticate.multi import MultiHandler, status_checker

def template():
    return """\
<html>
  <head><title>Please Sign In</title></head>
  <body>
    <h1>Please Sign In</h1>
    <div class="$css_class">$message</div>
    <form action="$action" method="post">
      <dl>
        <dt>OpenID Passurl:</dt>
        <dd><input type="text" name="openid" value="$value"></dd>
      </dl>
      <input type="submit" name="authform" />
      <hr />
    </form>
  </body>
</html>
"""

def passurl_urltouser(environ, url):
    return url.strip('/').split('/')[-1]

def render(template, **p):
    if sys.version_info >= (2,4):
        return string.Template(template()).substitute(
            **p
        )
    else:
        for k, v in p.items():
            template = template().replace('$'+k, v)
        return template

class OpenIDAuthHandler(object):
    """
    This middleware is triggered when the authenticate middleware catches 
    a 401 response. The form is submitted to the verify URL which the other
    middleware handles
    """
    def __init__(self, app, template, path_verify, baseurl='', charset=None):
        self.app = app
        self.template = template
        self.baseurl = baseurl
        self.path_verify = path_verify
        if charset is None:
            self.charset = ''
        else:
            self.charset = '; charset='+charset

    def __call__(self, environ, start_response):
        baseurl = self.baseurl or construct_url(
            environ, 
            with_query_string=False, 
            with_path_info=False
        )
        content = render(
            self.template,
            message='',
            value='',
            css_class='',
            action=baseurl + self.path_verify
        )
        start_response(
            "200 OK",
            [
                ('Content-Type', 'text/html'+self.charset),
                ('Content-Length', str(len(content)))
            ]
        )
        return [content]

def make_store(store, config):
    conn = None
    if store == 'file':
        from openid.store import filestore
        cstore = filestore.FileOpenIDStore(config)
    elif store == 'mysql':
        import MySQLdb
        from DBUtils.PersistentDB import PersistentDB
        from openid.store.sqlstore import MySQLStore
        from sqlalchemy.engine.url import make_url

        def create_conn(dburi):
            url = make_url(dburi)
            p={'db':url.database}
            if url.username:
                p['user'] = url.username
            if url.password:
                p['passwd'] = url.password
            if url.host:
                p['host'] = url.host
            if url.port:
                p['port'] = url.port
            return PersistentDB(MySQLdb, 1, **p).connection()
        conn = create_conn(config)
        cstore = MySQLStore(conn)
    else:
        raise Exception("Invalid store type %r"%store)
    return conn, cstore

class AuthOpenIDHandler:
    """
    The template should be setup from authkit.open_id.template.file or 
    authkit.open_id.template.obj before we get here!
    """
    def __init__(
        self, 
        app, 
        store_type, 
        store_config, 
        baseurl, 
        path_signedin, 
        template=None,
        session_middleware='beaker.session',
        path_verify='/verify', 
        path_process='/process',
        urltouser=None,
        charset=None,
        sreg_required=None,
        sreg_optional=None,
        sreg_policyurl=None,
        ax_attr=None
    ):
        self.conn, self.store = make_store(store_type, store_config)
        self.baseurl = baseurl
        self.template = template
        self.path_signedin = path_signedin
        self.path_verify = path_verify
        self.path_process = path_process
        self.session_middleware = session_middleware
        self.app = app
        self.urltouser = urltouser
        if charset is None:
            self.charset = ''
        else:
            self.charset = '; charset='+charset
        self.sreg_required = sreg_required
        self.sreg_optional = sreg_optional
        self.sreg_policyurl = sreg_policyurl
        
        if ax_attr is not None:
            # Make an Attribute Exchange Fetch Request message based on the 
            # attributes passed in
            self.ax_request = ax.FetchRequest()
            for attrInfo in ax_attr:
                self.ax_request.add(attrInfo)

    def __call__(self, environ, start_response):
        # If we are called it is because we want to sign in, so show the 
        if not environ.has_key(self.session_middleware):
            raise AuthKitConfigError(
                'The session middleware %r is not present. '
                'Have you set up the session middleware?'%(
                    self.session_middleware
                )
            )
        if environ.get('PATH_INFO') == self.path_verify:
            response = self.verify(environ, start_response)
            environ[self.session_middleware].save()
            return response
        elif environ.get('PATH_INFO') == self.path_process:
            response = self.process(environ, start_response)
            environ[self.session_middleware].save()
            return response
        else:
            return self.app(environ, start_response)

    def verify(self, environ, start_response):
        baseurl = self.baseurl or construct_url(
            environ, 
            with_query_string=False, 
            with_path_info=False
        )
        params = dict(paste.request.parse_formvars(environ))
        openid_url = params.get('openid')
        if not openid_url:
            response = render(
                self.template,
                message='Enter an identity URL to verify.',
                value='',
                css_class='',
                action=baseurl + self.path_verify
            )
            start_response(
                '200 OK', 
                [
                    ('Content-type', 'text/html'+self.charset),
                    ('Content-length', str(len(response)))
                ]
            )
            return response
    
        oidconsumer = self._get_consumer(environ)
       # import pdb; pdb.set_trace()
        try:
            request_ = oidconsumer.begin(openid_url)
        except consumer.DiscoveryFailure, exc:
            response = render(
                self.template,
                message='Error retrieving identity URL: %s' % (
                    cgi.escape(str(exc[0]))
                ),
                value=self._quoteattr(openid_url),
                css_class='error',
                action=baseurl + self.path_verify
            )
            start_response(
                '200 OK', 
                [
                    ('Content-type', 'text/html'+self.charset),
                    ('Content-length', str(len(response)))
                ]
            )
            return response
        else:
            if request_ is None:
                response = render(
                    self.template,
                    message='No OpenID services found for <code>%s</code>' % (
                        cgi.escape(openid_url),
                    ),
                    value=self._quoteattr(openid_url),
                    css_class='error',
                    action=baseurl + self.path_verify
                )
                start_response(
                    '200 OK', 
                    [
                        ('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))
                    ]
                )
                return response
            else:
                session = environ[self.session_middleware]
                if 'HTTP_REFERER' in environ and \
                        not environ['HTTP_REFERER'].endswith(self.path_verify) and \
                        not environ['HTTP_REFERER'].endswith(self.path_process):
                    session['referer'] = environ['HTTP_REFERER']

                if self.sreg_required or self.sreg_optional or self.sreg_policyurl:
                    required_list = []
                    if self.sreg_required:
                        required_list = [opt.strip() for opt in self.sreg_required.split(',')]
                    optional_list = []
                    if self.sreg_optional:
                        optional_list = [opt.strip() for opt in self.sreg_optional.split(',')]
                    sreg_request = sreg.SRegRequest(
                        required=required_list,
                        optional=optional_list,
                        policy_url=self.sreg_policyurl)
                    request_.addExtension(sreg_request)

                if hasattr(self, 'ax_request'):
                    # Add Attribute Exchange Fetch Request if set in
                    # initialization
                    request_.addExtension(self.ax_request)

                trust_root = baseurl
                return_to = baseurl + self.path_process

                if request_.shouldSendRedirect():
                    redirect_url = request_.redirectURL(
                        trust_root, return_to)

                    start_response(
                        '301 Redirect', 
                        [
                            ('Content-type', 'text/html'+self.charset),
                            ('Location', redirect_url)
                        ]
                    )
                    return []
                else:
                    # This gets called with sites such as myopenid.com
                    form_html = request_.formMarkup(
                        trust_root, return_to,
                        form_tag_attrs={'id':'openid_message'})
                    # Alter form so that it doesn't appear
                    #
                    # P J Kershaw 25/02/09
#                    content = """\
#                        <html><head><title>OpenID transaction in progress</title></head>
#                        <body onload='document.getElementById("%s").submit()'>
#                        %s
#                        </body></html>
#                    """%('openid_message', form_html)

                    content = """\
<html>
    <head>
        <title>OpenID transaction in progress</title>
        <script type="text/javascript">
            function doRedirect()
            {
                var elem;
                elem = document.getElementById("%s")
                elem.style.visibility="hidden";
                elem.submit();
            }
        </script>
    </head>
    <body onload='doRedirect()'>
        %s
    </body>
</html>
                    """%('openid_message', form_html)
                    start_response(
                        "200 OK",
                        [
                            ('Content-Type', 'text/html'+self.charset),
                            ('Content-Length', str(len(content)))
                        ]
                    )
                    return [content]

    def process(self, environ, start_response):
        baseurl = self.baseurl or construct_url(
            environ, 
            with_query_string=False, 
            with_path_info=False
        )
        value = ''
        css_class = 'error'
        message = ''

        # P J Kershaw 25/02/09
#        params = dict(paste.request.parse_querystring(environ))
        if environ['REQUEST_METHOD'] == "GET":
            params = dict(paste.request.parse_querystring(environ))
        else:
            # Reply from provider switches to POST method if content length
            # exceeds maximum for inclusion in URL.
            params = dict(paste.request.parse_formvars(environ))

        oidconsumer = self._get_consumer(environ)
        # Fixes #50
        info = oidconsumer.complete(
            dict(params), 
            params.get('openid.return_to')
        )

        if info.status == consumer.FAILURE and info.identity_url:
            fmt = "Verification of %s failed."
            message = fmt % (cgi.escape(info.identity_url),)
            environ['wsgi.errors'].write(
                "Passurl Message: %s %s"%(message,info.message)
            )
        elif info.status == consumer.SUCCESS:
            username = info.identity_url
            if info.endpoint.canonicalID:
                username = cgi.escape(info.endpoint.canonicalID)
            sreg_info = sreg.SRegResponse.fromSuccessResponse(info)
            if sreg_info:
                user_data = str(sreg.SRegResponse.fromSuccessResponse(info).getExtensionArgs())
            else:
                user_data = ""
            
            # Check for Attribute Exchange extension
            #
            # P J Kershaw
            axResponse = ax.FetchResponse.fromSuccessResponse(info)
            if axResponse is not None:
                if hasattr(self, 'ax_request'):
                    # Set request details to enable parsing of response with
                    # attribute aliases
                    axResponse.request = self.ax_request
                    
                axData = axResponse.getExtensionArgs()
                
                user_data += str({'ax':axData})

            # Set the cookie
            if self.urltouser:
                username = self.urltouser(environ, info.identity_url)
            environ['paste.auth_tkt.set_user'](username, user_data=user_data)
            # Return a page that does a meta refresh
            session = environ[self.session_middleware]
            if 'referer' in session:
                redirect_url = session.pop('referer')
            else:
                redirect_url = self.baseurl + self.path_signedin

            response = """
<HTML>
<HEAD>
<META HTTP-EQUIV="refresh" content="0;URL=%s">
<TITLE>Signed in</TITLE>
</HEAD>
<BODY>
<!-- You are sucessfully signed in. Redirecting... -->
</BODY>
</HTML>
            """ % (redirect_url)
            start_response(
                '200 OK', 
                [
                    ('Content-type', 'text/html'+self.charset),
                    ('Content-length', str(len(response)))
                ]
            )
            return response
        elif info.status == consumer.CANCEL:
            message = 'Verification cancelled'
        elif info.status == consumer.SETUP_NEEDED:
            if info.setup_url:
                message = '<a href=%s>Setup needed</a>' % (
                    self._quoteattr(info.setup_url),)
            else:
                message = 'Setup needed'
        else:
            environ['wsgi.errors'].write("Passurl Message: %s"%info.message)
            message = 'Verification failed.'
        value = self._quoteattr(info.identity_url)
        response = render(
            self.template,
            message=message,
            value=value,
            css_class=css_class,
            action=baseurl + self.path_verify
        )
        start_response(
            '200 OK', 
            [
                ('Content-type', 'text/html'+self.charset),
                ('Content-length', str(len(response)))
            ]
        )
        return response

    #
    # Helper methods
    #

    def _get_consumer(self, environ):
        session = environ[self.session_middleware]
        session['id'] = session.id
        oidconsumer = consumer.Consumer(session, self.store)
        oidconsumer.consumer.openid1_nonce_query_arg_name = 'passurl_nonce'
        session.save()
        return oidconsumer

    def _quoteattr(self, s):
        if s == None:
            s = ''
        qs = cgi.escape(s, 1)
        return '"%s"' % (qs,)

class OpenIDUserSetter(AuthKitUserSetter):
    def __init__(self, app, **options):
        app = AuthOpenIDHandler(
            app,
            store_type=options['store_type'], 
            store_config = options['store_config'],
            baseurl=options.get('baseurl',''),
            path_signedin=options['path_signedin'],
            path_process=options.get('path_process','/process'),
            template = options['template'],
            urltouser = options['urltouser'],
            charset = options['charset'],
            sreg_required=options['sreg_required'],
            sreg_optional=options['sreg_optional'],
            sreg_policyurl=options['sreg_policyurl'],
            session_middleware=options['session_middleware'],
            ax_attr=options['ax_attr']
        )
        self.app = app

    def __call__(self, environ, start_response):
        return self.app(environ, start_response)

def load_openid_config(
    app,
    auth_conf, 
    app_conf=None,
    global_conf=None,
    prefix='authkit.openid', 
):
    global template
    template_ = template
    template_conf = strip_base(auth_conf, 'template.')
    if template_conf:
        template_ = get_template(template_conf, prefix=prefix+'template.')
    urltouser = auth_conf.get('urltouser', None)
    if isinstance(urltouser, str):
        urltouser = eval_import(urltouser)
    for option in ['store.type', 'store.config', 'path.signedin']:
        if not auth_conf.has_key(option):
            raise AuthKitConfigError(
                'Missing the config key %s%s'%(prefix, option)
            )
    user_setter_params={
        'store_type': auth_conf['store.type'], 
        'store_config': auth_conf['store.config'],
        'baseurl': auth_conf.get('baseurl',''),
        'path_signedin': auth_conf['path.signedin'],
        'path_process': auth_conf.get('path.process','/process'),
        'template': template_,
        'urltouser': urltouser,
        'charset': auth_conf.get('charset'),
        'sreg_required': auth_conf.get('sreg.required'),
        'sreg_optional': auth_conf.get('sreg.optional'),
        'sreg_policyurl': auth_conf.get('sreg.policyurl'),
        'session_middleware': auth_conf.get('session.middleware','beaker.session'),
    }
    
    # Add an Attribute Exchange configuration items
    user_setter_params.update(_load_ax_config(auth_conf))

    auth_handler_params={
        'template':user_setter_params['template'],
        'path_verify':auth_conf.get('path.verify', '/verify'),
        'baseurl':user_setter_params['baseurl'],
        'charset':user_setter_params['charset'],
    }
    # The following lines were suggested in #59 but I don't know
    # why they are needed because you shouldn't be using the 
    # user management API.
    # authenticate_conf = strip_base(auth_conf, 'authenticate.')
    # app, authfunc, users = get_authenticate_function(
    #     app, 
    #     authenticate_conf, 
    #     prefix=prefix+'authenticate.', 
    #     format='basic'
    # )
    return app, auth_handler_params, user_setter_params


# AX Support
# 
# P J Kershaw
def _load_ax_config(auth_conf):
    '''Read configuration for attribute exchange'''
    ax_params = {'ax_attr': []}
    
    # Type URI field determines which attributes to include.  Other attribute
    # properties such alias, count and required may be set to defaults
    ax_attr_list = [k.replace('ax.typeuri.', '') for k in auth_conf.iterkeys()
                    if k.startswith('ax.typeuri.')]
    for i in ax_attr_list:
        typeURI = auth_conf['ax.typeuri.%s' % i]
        sCount = auth_conf.get('ax.count.%s' % i, '1')
        if sCount == ax.UNLIMITED_VALUES:
            count = sCount
        else:
            count = int(sCount)
            
        required = str(auth_conf.get('ax.required.%s' % i,'false')).lower()=='true'
        alias = auth_conf.get('ax.alias.%s' % i)
            
        attrInfo = ax.AttrInfo(typeURI, count=count, required=required, 
                               alias=alias)
        ax_params['ax_attr'] += [attrInfo]
      
    return ax_params
   
def make_passurl_handler(
    app,
    auth_conf, 
    app_conf=None,
    global_conf=None,
    prefix='authkit.openid', 
):
    app, auth_handler_params, user_setter_params = load_openid_config(
        app,
        auth_conf, 
        app_conf=None,
        global_conf=None,
        prefix='authkit.openid', 
    )
    # Note, the session middleware should already be setup by now
    # if we are not using beaker
    app = MultiHandler(app)
    app.add_method(
        'openid', 
        OpenIDAuthHandler,
        template=auth_handler_params['template'],
        path_verify=auth_handler_params['path_verify'],
        baseurl=auth_handler_params['baseurl'],
        charset = auth_handler_params['charset'],
    )
    app.add_checker('openid', status_checker)
    # XXX Some of this functionality should be moved into OpenIDAuthHandler
    app = OpenIDUserSetter(
        app,
        **user_setter_params
    )
    return app

# Backwards compatibility
PassURLSignIn = OpenIDAuthHandler
