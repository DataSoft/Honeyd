#
# Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
"""Basic Honeyd Web Server module, we try to do something with it."""

import sys
import os
import SimpleHTTPServer
import StringIO
import posixpath
import urllib
import time
import honeyd

__version__ = "0.1"

class HoneydServer:
    """Base Honeyd Web Server."""

    def __init__(self, RequestHandlerClass, root):
        self.root = root
        self.RequestHandlerClass = RequestHandlerClass

    def handle_request(self, request, client_address):
        """Handle one request, possibly blocking."""

        if self.verify_request(request, client_address):
            self.finish_request(request, client_address)
            self.close_request(request)

    def verify_request(self, request, client_address):
        return 1

    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""

        self.RequestHandlerClass(request, client_address, self)

    def close_request(self, request):
        """Called to clean up an individual request."""
        pass
        

class HoneydRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    """A wrapper to use the generic HTTP Request Handler."""

    server_version = "HoneydHTTP/" + __version__

    def __init__(self, request, client_address, server):
        self.request = request
        self.client_address = client_address
        self.server = server
        self.root = server.root

        self.setup()
        self.handle()
        self.finish()

    def send_head(self):
        """Serve a GET request."""

        if self.is_python():
            return self.run_python()

        # Regular file
        path = self.translate_path(self.path)
        f = None
        if os.path.isdir(path):
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        ctype = self.guess_type(path)
        if ctype.startswith('text/'):
            mode = 'r'
        else:
            mode = 'rb'
        try:
            f = open(path, mode)
        except IOError:
            self.send_error(404, "File not found")
            return None
        self.send_response(200)
        self.send_header("Content-type", ctype)
        sb = os.fstat(f.fileno())
        self.send_header("Content-Length", str(sb[6]))
        self.send_header("Last-Modified", self.date_time_string(sb[8]))
        self.end_headers()
        return f

    def date_time_string(self,now=0):
        """Return the current date and time formatted for a message header."""
        if not now:
            now = time.time()
        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(now)
        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
                self.weekdayname[wd],
                day, self.monthname[month], year,
                hh, mm, ss)
        return s

    def is_python(self):
        """Determines if the request is for a python script."""
        path = self.translate_path(self.path)
        i = path.rfind('?')
        if i >= 0:
            path, query = path[:i], path[i+1:]
        head, tail = os.path.splitext(path)
        return tail.lower() in (".py", ".pyw")

    def run_python(self):
        path = self.translate_path(self.path)
        head, tail = os.path.split(path)

        i = tail.rfind('?')
        if i >= 0:
            tail, query = tail[:i], tail[i+1:]
            entries = query.split('&')
            self.query = {}
            for entry in entries:
                kv = entry.split("=")
                self.query[kv[0]] = '='.join(kv[1:])
        else:
            self.query = None

        scriptname = head + '/' + tail
        if not os.path.exists(scriptname):
            self.send_error(404, "File not found")
            return

        execfile(scriptname)

    def log_message(self, format, *args):
        """Logs a message to Honeyd via syslog."""
        message = "%s - - [%s] %s" % (self.address_string(),
                                      self.log_date_time_string(),
                                      format%args)
        try:
            import honeyd
            honeyd.raw_log(message)
        except:
            sys.stderr.write(message + "\n")

    def address_string(self):
        """Return the client address."""
        return self.client_address

    def setup(self):
        self.rfile = StringIO.StringIO(self.request)
        self.wfile = StringIO.StringIO()

    def translate_path(self, path):
        """Translate a /-separated PATH to the local filename syntax.

        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)

        """
        path = posixpath.normpath(urllib.unquote(path))
        words = path.split('/')
        words = filter(None, words)
        path = self.root
        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir): continue
            path = os.path.join(path, word)
        if os.path.isdir(path):
            for index in "index.py", "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
        return path

    def send_nocache(self):
        """Sends headers that makes the results page non-cacheable."""
        self.send_header("Expires", "0");
        self.send_header("Last-Modified", self.date_time_string());
        self.send_header("Cache-Control", "no-cache, must-revalidate");
        self.send_header("Pragma", "no-cache");

    def finish(self):
        self.server.result = self.wfile.getvalue()

def make_server(root):
    return HoneydServer(HoneydRequestHandler, root);

def handle_request(server, request, client_address):
    server.handle_request(request, client_address)
    return server.result
    
def test():
    request = "GET / HTTP/1.0\r\n\r\n"
    server = HoneydServer(HoneydRequestHandler)
    server.handle_request(request, "127.0.0.1")
    print server.result

    request = "GET /test.py HTTP/1.0\r\n\r\n"
    server.handle_request(request, "127.0.0.1")
    print server.result

if __name__ == '__main__':
    test()
