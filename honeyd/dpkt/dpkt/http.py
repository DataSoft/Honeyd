# $Id: http.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

import cStringIO

def parse_headers(f):
    """Return dict of HTTP headers parsed from a file object."""
    d = {}
    while 1:
        line = f.readline()
        if not line:
            raise ValueError, 'premature end of headers'
        line = line.strip()
        if not line:
            break
        l = line.split(None, 1)
        if not l[0].endswith(':'):
            raise ValueError, 'invalid header: %r' % line
        d[l[0][:-1].lower()] = l[1]
    return d

def parse_body(f, headers):
    """Return HTTP body parsed from a file object, given HTTP header dict."""
    if headers.get('transfer-encoding', '').lower() == 'chunked':
        # ChunKing Express
        l = []
        found_end = False
        while 1:
            n = int(f.readline(), 16)
            if n == 0:
                found_end = True
            buf = f.read(n)
            if buf:
                l.append(buf)
            else:
                break
        if not found_end:
            raise ValueError, 'premature end of chunked body'
        body = ''.join(l)
    elif 'content-length' in headers:
        n = int(headers['content-length'])
        body = f.read(n)
        if len(body) != n:
            raise ValueError, 'short body (missing %d bytes)' % (n - len(body))
    elif 'content-type' in headers:
        body = f.read()
    else:
        # XXX - need to handle HTTP/0.9
        body = ''
    return body

class Message(object):
    """Hypertext Transfer Protocol headers + body."""
    __hdr_defaults__ = {}
    headers = None
    body = None
    
    def __init__(self, *args, **kwargs):
        if args:
            self.unpack(args[0])
        else:
            self.headers = {}
            self.body = ''
            for k, v in self.__hdr_defaults__.iteritems():
                setattr(self, k, v)
            for k, v in kwargs.iteritems():
                setattr(self, k, v)
    
    def unpack(self, buf):
        f = cStringIO.StringIO(buf)
        # Parse headers
        self.headers = parse_headers(f)
        # Parse body
        self.body = parse_body(f, self.headers)
        # Save the rest
        self.data = f.read()

    def __len__(self):
        return len(str(self))
    
    def __str__(self):
        hdrs = ''.join([ '%s: %s\r\n' % t for t in self.headers.iteritems() ])
        return '%s\r\n%s' % (hdrs, self.body)

class Request(Message):
    """Hypertext Transfer Protocol Request."""
    __hdr_defaults__ = {
        'method':'GET',
        'uri':'/',
        'version':'1.0'
        }
    __methods = dict.fromkeys((
        'GET', 'PUT', 'ICY',
        'COPY', 'HEAD', 'LOCK', 'MOVE', 'POLL', 'POST',
        'BCOPY', 'BMOVE', 'MKCOL', 'TRACE', 'LABEL', 'MERGE',
        'DELETE', 'SEARCH', 'UNLOCK', 'REPORT', 'UPDATE', 'NOTIFY',
        'BDELETE', 'CONNECT', 'OPTIONS', 'CHECKIN',
        'PROPFIND', 'CHECKOUT', 'CCM_POST',
        'SUBSCRIBE', 'PROPPATCH', 'BPROPFIND',
        'BPROPPATCH', 'UNCHECKOUT', 'MKACTIVITY',
        'MKWORKSPACE', 'UNSUBSCRIBE', 'RPC_CONNECT',
        'VERSION-CONTROL',
        'BASELINE-CONTROL'
        ))

    def unpack(self, buf):
        f = cStringIO.StringIO(buf)
        line = f.readline()
        l = line.split()
        if len(l) != 3 or l[0] not in self.__methods or \
           not l[2].startswith('HTTP/'):
            raise ValueError, 'invalid request: %r' % line
        self.method = l[0]
        self.uri = l[1]
        self.version = l[2][5:]
        Message.unpack(self, f.read())

    def __str__(self):
        return '%s %s HTTP/%s\r\n' % (self.method, self.uri, self.version) + \
               Message.__str__(self)

class Response(Message):
    """Hypertext Transfer Protocol Response."""
    __hdr_defaults__ = {
        'version':'1.0',
        'status':'200',
        'reason':'OK'
        }

    def unpack(self, buf):
        f = cStringIO.StringIO(buf)
        line = f.readline()
        l = line.split()
        if len(l) < 2 or not l[0].startswith('HTTP/') or not l[1].isdigit():
            raise ValueError, 'invalid response: %r' % line
        self.version = l[0][5:]
        self.status = l[1]
        self.reason = l[2]
        Message.unpack(self, f.read())

    def __str__(self):
        return 'HTTP/%s %s %s\r\n' % \
               (self.version, self.status, self.reason) + Message.__str__(self)

if __name__ == '__main__':
    import unittest

    class HTTPTest(unittest.TestCase):
        def test_parse_request(self):
            s = """POST /main/redirect/ab/1,295,,00.html HTTP/1.0\r\nReferer: http://www.email.com/login/snap/login.jhtml\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.75 [en] (X11; U; OpenBSD 2.8 i386; Nav)\r\nHost: ltd.snap.com\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\nAccept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\nContent-type: application/x-www-form-urlencoded\r\nContent-length: 61\r\n\r\nsn=em&mn=dtest4&pw=this+is+atest&fr=true&login=Sign+in&od=www"""
            r = Request(s)
            assert r.method == 'POST'
            assert r.uri == '/main/redirect/ab/1,295,,00.html'
            assert r.body == 'sn=em&mn=dtest4&pw=this+is+atest&fr=true&login=Sign+in&od=www'
            assert r.headers['content-type'] == 'application/x-www-form-urlencoded'
            try:
                r = Request(s[:60])
                assert 'invalid headers parsed!'
            except ValueError:
                pass

        def test_format_request(self):
            r = Request()
            assert str(r) == 'GET / HTTP/1.0\r\n\r\n'
            r.method = 'POST'
            r.uri = '/foo/bar/baz.html'
            r.headers['content-type'] = 'text/plain'
            r.headers['content-length'] = '5'
            r.body = 'hello'
            assert str(r) == 'POST /foo/bar/baz.html HTTP/1.0\r\ncontent-length: 5\r\ncontent-type: text/plain\r\n\r\nhello'
            r = Request(str(r))
            assert str(r) == 'POST /foo/bar/baz.html HTTP/1.0\r\ncontent-length: 5\r\ncontent-type: text/plain\r\n\r\nhello'
            
    unittest.main()
