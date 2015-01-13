from authkit.authenticate import middleware, sample_app
from beaker.middleware import SessionMiddleware

app = middleware(
    sample_app,
    setup_method='openid, cookie',
    openid_path_signedin='/private',
    openid_store_type='file',
    openid_store_config='',
    openid_charset='UTF-8',
    cookie_secret='secret encryption string',
    cookie_signoutpath = '/signout',
)
app = SessionMiddleware(
    app, 
    key='authkit.open_id', 
    secret='some secret',
)
if __name__ == '__main__':
    from paste.httpserver import serve
    serve(app, host='0.0.0.0', port=8080)
