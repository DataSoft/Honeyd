#!/usr/local/bin/python
import sys
import os
import re
import string
import stat

try:
    root = sys.argv[1]
    if not re.search("\/$", root):
        root += "/"
except:
    root = "/usr/home/provos/src/generate/webdocs/"

def bad_request():
    print """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<HTML><HEAD>
<TITLE>501 Method Not Implemented</TITLE>
</HEAD><BODY>
<H1>Method Not Implemented</H1>
Method to /index.html not supported.<P>
Invalid method in request<P>
</BODY></HTML>"""
    sys.stdout.flush()
    sys.exit(1)

def bad_url(url):
    m = re.compile("xurlx")
    line = '''HTTP/1.0 404 Not Found
Server: MiniServer/0.6
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<HTML><HEAD>
<TITLE>404 Not Found</TITLE>
</HEAD><BODY>
<H1>Not Found</H1>
The requested URL /xurlx was not found on this server.<P>
</BODY></HTML>'''

    line = m.sub(url, line)
    print line
    sys.stdout.flush()
    sys.exit(1)

def serve_url(host, url):
    print >>sys.stderr, "%s requests (%s, %s)" % (srcipaddr, host, url)

    seq = string.split(url, "?")

    if seq[0] == "":
        seq[0] = "index.html"

    if host:
        try:
            sb = os.stat(root+host)
        except:
            sb = None

        if sb and stat.S_ISDIR(sb[0]):
            newurl = host+'/'+seq[0]
        else:
            newurl = seq[0]
    else:
        newurl = seq[0]

    try:
        rp = os.path.realpath(root+newurl)
    except:
        bad_url(url)

    if not re.match("^.*"+root, rp):
        bad_url(url)

    if re.match("^.*/$", rp):
        rp += "index.html"

    try:
        sb = os.stat(rp)
    except:
        bad_url(url)

    if stat.S_ISDIR(sb[0]):
        rp += "/index.html"
        
    try:
        f = open(rp, "rb")
    except:
        bad_url(url)
        sys.exit(1)

    m = re.compile("xtypex")
    header = '''HTTP/1.0 200 OK
Server: MiniServer/0.6
Connection: close
Content-Type: xtypex
'''

    if re.match("^.*\.(html|py)", rp):
        header = m.sub("text/html", header)
    elif re.match("^.*\.jpg", rp):
        header = m.sub("image/jpeg", header)
    else:
        header = m.sub("application/octet-stream", header)

    print header
        
    while 1:
        try:
            l = f.readline()
        except:
            l = none

        if not l:
            break

        print l,

    sys.exit(0)

# Main

try:
    srcipaddr = os.environ['HONEYD_IP_SRC']
except:
    srcipaddr = "127.0.0.1"

gotrequest = 0
host = None
while 1:
    try:
        l = raw_input("")
    except EOFError:
        sys.exit()

    if re.match("^\s*$", l, re.MULTILINE):
        break

    m = re.match("^get /(?P<url>.*) HTTP/1.[01]", l, re.IGNORECASE)
    if m:
        url = m.group('url')
        gotrequest = 1
        continue

    if not gotrequest:
        bad_request()

    m = re.match("^Host: +(?P<host>[^\s:]*)", l, re.IGNORECASE)
    if m:
        host = m.group('host')
        continue

serve_url(host, url)
