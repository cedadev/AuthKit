"""
See the README.txt file for how to setup and use this example.

Note that the AuthKit middleware is by default only setup to intercept
401 responses due to NotAuthenticated errors. This means if you try to
access a resource when you aren't signed in and you don't have access
to it you will be prompted to sign in. If you are signed in you will
be shown the server's default 403 error page. If you want to be prompted
to sign in under these circumstances too, uncomment this line to the 
middleware setup at the end of this example::

    # setup_intercept = "401, 403",

"""
from paste.httpexceptions import HTTPExceptionHandler
from authkit.authenticate import middleware
from authkit.authorize import authorize
from authkit.users.sqlalchemy_driver import UsersFromDatabase
from authkit.permissions import ValidAuthKitUser, HasAuthKitRole, HasAuthKitGroup

class SampleApp:
    
    # Application setup
    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO')
        if path == '/user':
            return self.user(environ, start_response)
        elif path == '/admin':
            return self.admin(environ, start_response)
        elif path == '/group':
            return self.group(environ, start_response)
        elif path == '/':
            return self.index(environ, start_response)
        else:
            start_response("404 Not Found", [("Content-type","text/plain")])
            return ["Not Found"]

    def _access_granted(self, start_response, message):
        start_response("200 OK", [("Content-type","text/html")])
        return [
            "<html><head><title>AuthKit Database Example</title></head>",
            "<body><h1>AuthKit Database Example</h1>",
            message,
            "</body></html>"
        ]

    # Induvidual pages
    def index(self, environ, start_response):
        return self._access_granted(
            start_response, 
            """
            <p>This page is public, try visiting the following pages:</p>
            <ul>
            <li><a href="/user">Any signed in user can access this page</a></li>
            <li><a href="/admin">Only signed in users with the <tt>admin</tt> role have access [ben]</a></li>
            <li><a href="/group">Only signed in users in the <tt>pylons</tt> group have access [james]</a></li>
            </ul>
            """
        )
        
    @authorize(ValidAuthKitUser()) # Note we don't use RemoteUser() here because we only want users in the AuthKit database
    def user(self, environ, start_response):
        return self._access_granted(start_response, "Any user in the database can access this")
        
    @authorize(HasAuthKitRole(["admin"]))
    def admin(self, environ, start_response):
        return self._access_granted(start_response, "You have the <tt>admin</tt> role.")
        
    @authorize(HasAuthKitGroup(["pylons"]))
    def group(self, environ, start_response):
        return self._access_granted(start_response, "You are in the <tt>pylons</tt> group.")

app = SampleApp()
# Not needed, included by the authenticate middleware
#app = HTTPExceptionHandler(app)
app = middleware(
    app,
    setup_method='form,cookie',
    cookie_secret='secret encryption string',
    form_authenticate_user_type = "authkit.users.sqlalchemy_driver:UsersFromDatabase",
    form_authenticate_user_data = "model",
    cookie_signoutpath = '/signout',
    # setup_intercept = "401, 403",
)
app = HTTPExceptionHandler(app)
if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename='test.log',
                    filemode='w')

    from paste.httpserver import serve
    serve(app, host='0.0.0.0', port=8080)
