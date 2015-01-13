#!/usr/bin/env python

"""
This code demonstrates some of the features of authkit.authorize.

Start the server with::

    python authorize.py
    
Then visit http://localhost:8080/ and you should see the output from the
``index()`` method which invites you to try some of the links. 

Each method linked to is implemented using a different means of checking
the permission.

In the ``__call__`` method, the code which implements the permission 
attribute checking also demonstrates the use of authorize ``middleware``.

If you sign in with a user other than ``james``, you will be signed in
but denied access to the resources.

Close your browser to clear the HTTP authentication cache and try the 
example again.
"""

from authkit.permissions import UserIn
from authkit.authorize import authorized, authorize, PermissionError
from authkit.authorize import middleware as authorize_middleware
from paste import httpexceptions

class NoSuchActionError(httpexceptions.HTTPNotFound):
    pass

class AuthorizeExampleApp:
    
    def __call__(self, environ, start_response):
        if environ['PATH_INFO'] == '/':
            method = 'index'
        else:
            method = environ['PATH_INFO'].split('/')[1]
        if not hasattr(self, method):
            raise NoSuchActionError('No such method')
        app = getattr(self,method)
        # This facilitates an alternative way you might want to check permisisons
        # rather than using an authorize() decorator
        if hasattr(app, 'permission'):
            app = authorize_middleware(app, app.permission)
        return app(environ, start_response) 

    def index(self, environ, start_response):
        start_response('200 OK', [('Content-type','text/html')])
        return ['''
            <html>
            <head>
            <title>AuthKit Authorize Example</title>
            </head>
            <body>
            <h1>Authorize Example</h1>
            <p>Try the following links. You should only be able to sign 
            in as user <tt>james</tt> with the password the same as the 
            username.</p>
            <ul>
               <li><a href="/mid_method_test">Mid Method</a></li>
               <li><a href="/decorator_test">Decorator</a></li>
               <li><a href="/attribute_test">Attribute (middleware)</a></li>
            </ul>
            <p>Once you have signed in you will need to close your 
            browser to clear the authentication cache.</p>
            </body>
            </html>
        ''']

    def mid_method_test(self, environ, start_response):
        """Authorize using a mid-method permissions check"""
        if authorized(environ, UserIn(users=['james'])):
            start_response('200 OK', [('Content-type','text/html')])
            return ['Access granted to /mid_method_test']
        else:
            start_response('200 OK', [('Content-type','text/html')])
            return ['User is not authorized']

    @authorize(UserIn(users=['james']))
    def decorator_test(self, environ, start_response):
        """Authorize using a decorator"""
        start_response('200 OK', [('Content-type','text/html')])
        return ['Access granted to /decorator_test']

    def attribute_test(self, environ, start_response):
        """Authorize using a permission attribute"""
        start_response('200 OK', [('Content-type','text/html')])
        return ['Access granted to /attribute_test']
    attribute_test.permission = UserIn(users=['james'])

if __name__ == '__main__':
    
    from paste.httpserver import serve
    from authkit.authenticate import middleware
    
    def valid(environ, username, password):
        """
        Sample, very insecure validation function
        """
        return username == password
        
    app = httpexceptions.make_middleware(AuthorizeExampleApp())
    app = middleware(
        app, 
        setup_method='basic', 
        basic_realm='Test Realm', 
        basic_authenticate_function=valid
    )
    print """
Clear the HTTP authentication first by closing your browser if you have been
testing other basic authentication examples on the same port.

You will be able to sign in as any user as long as the password is the same as
the username, but all users apart from `james' will be denied access to the
resources.
"""
    
    
    serve(app, host='0.0.0.0', port=8080)
