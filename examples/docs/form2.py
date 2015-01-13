# -*- coding: utf-8 -*-

"""
Simple form example which uses a custom validation function to authenticate
users. The username is ``test`` the password is ``password``.
"""
from authkit.authenticate import middleware, sample_app

def valid(environ, username, password):
    return username == 'test' and password == 'password'

app = middleware(
    sample_app,
    setup_method='form,cookie',
    cookie_secret='secret encryption string',
    form_authenticate_function = valid,
    form_charset='UTF-8',
    cookie_signoutpath = '/signout',
    form_method='get',
)

if __name__ == '__main__':
    from paste.httpserver import serve
    serve(app, host='0.0.0.0', port=8080)
