from authkit.authenticate import middleware, sample_app 
from authkit.authenticate.digest import digest_password

def digest(environ, realm, username):
    password = username
    return digest_password(realm, username, password)

config = {
    'authkit.setup.method':'digest',
    'authkit.digest.realm':'Test Realm',
    'authkit.digest.authenticate.function':digest,
    'authkit.setup.enable':'True',
}

app = middleware(
    sample_app,
    app_conf = config    
)

if __name__ == '__main__':
    from paste.httpserver import serve
    serve(app, host='0.0.0.0', port=8080)

