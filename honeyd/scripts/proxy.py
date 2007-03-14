#!/usr/local/bin/python
#
# Spam Bait and Analyzer for Honeyd
#
# Copyright 2003 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
# For the license refer to the main source code of Honeyd.
import signal
import os
import string
import time
import posix
import sys
import re
import DNS
import httplib
from random import Random

def bad_port(hostname):
    text = '''HTTP/1.0 503 Connect failed
Content-Type: text/html

<html>
<head>
<title>Internet Junkbuster: Connect failed</title>
</head>
<body bgcolor="#f8f8f0" link="#000078" alink="#ff0022" vlink="#787878">
<h1><center><strong>Internet J<small>UNK<i><font color="red">BUSTER</font></i></small></strong></center></h1>TCP connection to \'xmagic_magicx\' failed: Operation not permitted.
<br></body>
</html>'''
    p = re.compile('xmagic_magicx')
    text = p.sub(hostname, text)
    print text
    sys.stdout.flush()

def connect_failed(address, reason="Operation now in progress"):
    text = '''HTTP/1.0 503 Connect failed
Content-Type: text/html

<html>
<head>
<title>Internet Junkbuster: Connect failed</title>
</head>
<body bgcolor="#f8f8f0" link="#000078" alink="#ff0022" vlink="#787878">
<h1><center><strong>Internet J<small>UNK<i><font color="red">BUSTER</font></i></small></strong></center></h1>TCP connection to \'xmagic_magicx\' failed: xreason_reasonx.
<br></body>
</html>'''
    p = re.compile('xmagic_magicx')
    text = p.sub(address, text)
    p = re.compile('xreason_reasonx')
    text = p.sub(reason, text)
    print text
    sys.stdout.flush()

def bad_domain(domain):
    text = '''HTTP/1.0 404 Non-existent domain
Content-Type: text/html

<html>
<head>
<title>Internet Junkbuster: Non-existent domain</title>
</head>
<body bgcolor="#f8f8f0" link="#000078" alink="#ff0022" vlink="#787878">
<h1><center><strong>Internet J<small>UNK<i><font color="red">BUSTER</font></i></small></strong></center></h1>No such domain: xmagic_magicx
</body>
</html>'''
    p = re.compile('xmagic_magicx')
    text = p.sub(domain, text)
    print text
    sys.stdout.flush()

def good_port():
    print '''HTTP/1.0 200 Connection established
Proxy-Agent: IJ/2.0.2
'''
    sys.stdout.flush()

def bad_connection():
    print '''HTTP/1.0 400 Invalid header received from browser
'''
    sys.stdout.flush()

def eat_input():
    list = []
    while 1:
        signal.alarm(30)
        try:
            g = raw_input("")
        except EOFError:
            sys.exit()
        signal.alarm(0)

        r = re.compile('[\r\n]*')
        g = r.sub("", g)
        if g == "":
            break
        list.append(g)

    return list

def is_gooddomain(host):
    a = DNS.DnsRequest(host, qtype = 'a').req().answers;
    for record in a:
        if record['typename'] == "A":
            return record['data']
        
    return

def is_ipaddr(host):
    return (re.match("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", host))

#
# main
#

try:
    srcipaddr = os.environ['HONEYD_IP_SRC']
except:
    srcipaddr = "127.0.0.1"

allowed_hosts = {
    "www.yahoo.com" : "^.*",
    "www.google.com" : "^.*",
    "www.alltheweb.com" : "^.*",
    "proxychecker.go-mailing.com" : "^.*",
    "pics.ebay.com" : "^.*\.(jpg|gif|png)$",
    "www.ebay.com" : "^/(index.html)?$",
    "slashdot.org" : "^/(index.html|graphics/.*\.(gif|jpg|png))?$",
    "www.gnu.org" : "^/(index.html|graphics/.*\.(gif|jpg|png))?$",
    "images.slashdot.org" : "^.*\.(jpg|gif|png)$",
    "images2.slashdot.org" : "^.*\.(jpg|gif|png)$",
    "www.jstor.org" : "^/(index.html|graphics/.*\.(gif|jpg|png))?$",
    "www.sina.com" : "^/(index.html|.*\.(gif|jpg|png))?$",
    "www.sina.com.cn" : "^/(index.html|.*\.(gif|jpg|png))?$",
    "image.sina.com.cn" : "^.*\.(jpg|gif|png)$",
    "image2.sina.com.cn" : "^.*\.(jpg|gif|png)$",
    "www.intel.com" : "^/(index.html|.*\.(gif|jpg|png))?$",
    "www.sun.com" : "^/(index.html|.*\.(gif|jpg|png))?$",
    "www.biomedcentral.com" : "^/(index.html|.*\.(gif|jpg|png))?$",
    "www.sciencedirect.com" : "^/(index.html|.*\.(gif|jpg|png))?$",
    "digstream.go.com": "^/digstream/autoupdate.xml$",
    "www.ingenta.com" : "^/(index.html|.*\.(gif|jpg|png))?$",
    }

sys.argv.pop(0)

if len(sys.argv):
    execprg = sys.argv[0]

DNS.ParseResolvConf()

while 1:
    signal.alarm(30)
    try:
        g = raw_input("")
    except EOFError:
        sys.exit()
    signal.alarm(0)
    
    m = re.match("^connect\s+(?P<host>.*)\s+http", g, re.IGNORECASE)
    if m:
        eat_input()
        hostname = m.group('host')
        m = re.match("^(?P<host>.*):(?P<port>[0-9]+)$", hostname)
        if m:
            host = m.group('host')
            port = m.group('port')
        else:
            port = "80"

        if port != "25":
            bad_port(hostname);
            sys.exit()

        if is_ipaddr(host):
            try:
                hostname = DNS.revlookup(host)
            except:
                hostname = ""
        elif re.match("^.*\.(edu|com|org)$", host):
            hostname = host
        else:
            hostname = ""

        good_port();

        arguments = [sys.argv[0]]
        if hostname != "":
            arguments.append("-h")
            arguments.append(hostname)
        for arg in sys.argv[1:]:
            arguments.append(arg)

        posix.execv(execprg, arguments)
        print text
        sys.exit()

    # General proxy request
    m = re.match("^GET\s+http://(?P<host>[^/ ]*)(?P<uri>/?[^ ]*)\s+HTTP",
                 g, re.IGNORECASE)
    if m:
        host = m.group('host')
        uri = m.group('uri')
        if uri == "":
            uri = "/"

        if is_ipaddr(host):
            eat_input()
            time.sleep(10)
            connect_failed(host)
            sys.exit()

        # Check if the domain name is any good
        m = is_gooddomain(host)
        if m:
            req = eat_input()

            # Check if this is an allowed host
            okay = 1
            try:
                search = allowed_hosts[string.lower(host)];
                if not re.match(search, uri, re.IGNORECASE):
                    okay = 0
            except:
                okay = 0

            if okay == 0:
                print >> sys.stderr, "Denied request to "+host+uri+" from "+ srcipaddr,
                time.sleep(2)
                connect_failed(host, "Broken pipe")
                sys.exit()
            else:
                print >> sys.stderr, "Allowing request to "+host+uri+" from "+ srcipaddr,


            headers = {}
            for line in req:
                header = string.split(line, ":", 1)
                headers[header[0]] = header[1]

            conn = httplib.HTTPConnection(host)
            try:
                conn.request("GET", uri, "", headers)
            except:
                connect_failed(host, "Broken pipe")
                sys.exit()
                
            response = conn.getresponse()

            print "HTTP/1.0", response.status, response.reason
            if response.getheader('date'):
                print 'Date:', response.getheader('date')
            if response.getheader('server'):
                print 'Server:', response.getheader('server')
            if response.getheader('mime-version'):
                print 'Mime-Version:', response.getheader('Mime-Version')
            if response.getheader('accept-ranges'):
                print 'Accept-Ranges:', response.getheader('accept-ranges')
            if response.getheader('expires'):
                print 'Expires:', response.getheader('expires')
            if response.getheader('vary'):
                print 'Vary:', response.getheader('vary')
            if response.getheader('content-type'):
                print 'Content-Type:', response.getheader('content-type')
            if response.getheader('content-encoding'):
                print 'Content-Encoding:', response.getheader('content-encoding')
            if response.getheader('content-length'):
                print 'Content-Length:', response.getheader('content-length')
            print

            if response.status == 200:
                data = response.read()
                print data
            conn.close()
        else:
            eat_input()
            bad_domain(host)
        sys.exit()
    else:
        bad_connection()
        sys.exit()
