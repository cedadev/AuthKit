from authkit.authenticate import middleware, sample_app

app = middleware(
    sample_app,
    setup_method='redirect,cookie',
    redirect_url='http://3aims.com',
    cookie_secret='asdasd'
)
if __name__ == '__main__':
    from paste.httpserver import serve
    serve(app, host='0.0.0.0', port=8080)
