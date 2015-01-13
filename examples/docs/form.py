# -*- coding: utf-8 -*-

from authkit.authenticate import middleware, sample_app

def user_data(state):
    return 'User data string'

app = middleware(
    sample_app,
    setup_method='form,cookie',
    cookie_secret='secret encryption string',
    form_authenticate_user_data = """
        الإعلاني:9406649867375c79247713a7fb81edf0
        username2:4e64aba9f0305efa50396584cfbee89c
    """,
    form_authenticate_user_encrypt = 'authkit.users:md5',
    form_authenticate_user_encrypt_secret = 'some secret string',
    form_charset='UTF-8',
    # For overriding proxied defaults:
    # form_action = 'http://localhost/forms/private',
    cookie_signoutpath = '/signout',
    form_userdata = user_data,
)

if __name__ == '__main__':
    from paste.httpserver import serve
    serve(app, host='0.0.0.0', port=8080)
