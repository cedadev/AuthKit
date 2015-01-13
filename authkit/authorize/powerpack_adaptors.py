"""PowerPack specific code to facilitate using AuthKit with Pylons
"""

from decorator import decorator
from authkit.authorize import PermissionSetupError
from authkit.authorize import NotAuthenticatedError, NotAuthorizedError
from authkit.authorize import authorize_request as authkit_authorize_request

def authorize(permission):
    """
    This is a decorator which can be used to decorate a Pylons controller action.
    It takes the permission to check as the only argument and can be used with
    all types of permission objects.
    """
    def validate(func, state, *args, **kwargs):
        all_conf = state.environ.get('authkit.config')
        if all_conf is None:
            raise Exception('Authentication middleware not present')
        if all_conf.get('setup.enable', True) is True:
            def app(environ, start_response):
                return func(state, *args, **kwargs)
            return permission.check(app, state.environ, state.start_response)
        else:
            return func(state, *args, **kwargs)
    return decorator(validate)

def authorize_request(state, permission):
    """
    This function can be used within a controller action to ensure that no code 
    after the function call is executed if the user doesn't pass the permission
    check specified by ``permission``.

    .. Note ::

        Unlike the ``authorize()`` decorator or
        ``authkit.authorize.middleware`` middleware, this function has no
        access to the WSGI response so cannot be used to check response-based
        permissions.  Since almost all AuthKit permissions are request-based
        this shouldn't be a big problem unless you are defining your own 
        advanced permission checks.
    """
    authkit_authorize_request(state.environ, permission)

def authorized(state, permission):
    """
    Similar to the ``authorize_request()`` function with no access to the
    request but rather than raising an exception to stop the request if a
    permission check fails, this function simply returns ``False`` so that you
    can test permissions in your code without triggering a sign in. It can
    therefore be used in a controller action or template.

    Use like this::

        if authorized(permission):
            return Response('You are authorized')
        else:
            return Response('Access denied')
 
    """
    try:
        authorize_request(state, permission)
    except (NotAuthorizedError, NotAuthenticatedError):
        return False
    else:
        return True

