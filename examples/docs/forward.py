from authkit.authenticate import middleware

def sample_app(environ, start_response):
    """
    A sample WSGI application that returns a 401 status code when the path 
    ``/private`` is entered, triggering the authenticate middleware to 
    forward to ``/signin`` where the user is prompted to sign in. 

    If the sign in is successful a cookie is set and the user can visit
    the ``/private`` path.

    The path ``/signout`` will display a signed out message if 
    and sign the user out if cookie_signout = '/signout' is specified in
    the middelware config.

    The path ``/`` always displays the environment.
    """
    if environ['PATH_INFO']=='/private' and not environ.has_key('REMOTE_USER'):
        start_response('401 Not signed in', [])
    elif environ['PATH_INFO'] == '/signout':
        start_response('200 OK', [('Content-type', 'text/plain')])
        if environ.has_key('REMOTE_USER'):
            return ["Signed Out"]
        else:
            return ["Not signed in"]
    elif environ['PATH_INFO'] == '/signin':
        page = """
            <html>
            <body>
            %s
            <form action="/signin">
            Username: <input type="text" name="username" /> 
            Password: <input type="password" name="password" />
            <br /> 
            <input type="submit" value="Sign in" />
            </body>
            </html>
            """
        if not environ.get('QUERY_STRING'):
            start_response(
                '200 Sign in required',
                [('Content-type', 'text/html')]
            )
            return [page%'<p>Please Sign In</p>']
        else:
            # Quick and dirty sign in check, do it properly in your code
            params = {}
            for part in environ['QUERY_STRING'].split('&'):
                params[part.split("=")[0]] = part.split('=')[1]
            if params['username'] and params['username'] == params['password']:
                start_response('200 OK', [('Content-type', 'text/html')])
                environ['paste.auth_tkt.set_user'](params['username'])
                return ["Signed in."]
            else:
                start_response('200 OK', [('Content-type', 'text/html')])
                return [page%'<p>Invalid details</p>']
    
    start_response('200 OK', [('Content-type', 'text/plain')])
    result = ['You Have Access To This Page.\n\nHere is the environment...\n\n']
    for k,v in environ.items():
        result.append('%s: %s\n'%(k,v))
    return result
  

app = middleware(
    sample_app,
    setup_method='forward,cookie',
    forward_signinpath = '/signin',
    cookie_signoutpath = '/signout',
    cookie_secret = 'somesecret',
)

if __name__ == '__main__':
    from paste.httpserver import serve
    serve(app, host='0.0.0.0', port=8080)

