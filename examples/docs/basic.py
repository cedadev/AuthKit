from authkit.authenticate import middleware, sample_app 

def valid(environ, username, password):
    return username == password

app = middleware(
    sample_app, 
    setup_method='basic', 
    basic_realm='Test Realm', 
    basic_authenticate_function=valid
)

if __name__ == '__main__':
    from paste.httpserver import serve
    serve(app, host='0.0.0.0', port=8080)

