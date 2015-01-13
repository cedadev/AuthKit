from authkit.authenticate import middleware, sample_app 
from authkit.authenticate.digest import digest_password

def digest(environ, realm, username):
    password = username
    return digest_password(realm, username, password)

app = middleware(
    sample_app,
    setup_method='digest',
    digest_realm='Test Realm',
    digest_authenticate_function=digest
)

if __name__ == '__main__':
    from paste.httpserver import serve
    serve(app, host='0.0.0.0', port=8080)

