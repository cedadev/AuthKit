"""
This is the same as the authorize.py example but it tests that the ``authkit.setup.enable = false`` option also disables authorisation checks.
"""

from authorize import *


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
        setup_enable=False,
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
