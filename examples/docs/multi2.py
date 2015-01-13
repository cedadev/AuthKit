"This example checks AuthKit's streaming ability"

from authkit.authenticate import middleware, sample_app 
import time

class AppClass(object):

    def __init__(self, environ, start_response):
        self.environ = environ
        self.start_response = start_response
        self.pos = 0
        self.data = [1,2,3,4,5]
        
    def __iter__(self):
        self.start_response('200 OK', [('Content-type','text/html')])
        return self

    def next(self):
        time.sleep(1)
        if self.pos < len(self.data):
            res = str(self.data[self.pos])
            self.pos += 1
            return res
        else:
            raise StopIteration

def generator(environ, start_response):
    start_response('200 OK', [('Content-type','text/html')])
    pos = 0
    data = [1,2,3,4,5]
    while pos < len(data):
        time.sleep(1)
        yield str(data[pos])
        pos += 1

app = AppClass
#app = generator
#app = sample_app

def valid(environ, username, password):
    return username == password

app = middleware(
    app, 
    setup_method='basic', 
    basic_realm='Test Realm', 
    basic_authenticate_function=valid
)

if __name__ == '__main__':
    from paste.httpserver import serve
    serve(app, host='0.0.0.0', port=8080)

