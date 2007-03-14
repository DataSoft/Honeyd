/*
 * Copyright (c) 2005 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#ifndef _PROXY_MESSAGES_H_
#define _PROXY_MESSAGES_H_

static struct keyvalue badport[] = {
	{ "junkbuster", "HTTP/1.0 503 Connect failed\r\nContent-Type: text/html\r\n\r\n<html>\r\n<head>\r\n<title>Internet Junkbuster: Connect failed</title>\r\n</head>\r\n<body bgcolor=\"#f8f8f0\" link=\"#000078\" alink=\"#ff0022\" vlink=\"#787878\">\r\n<h1><center><strong>Internet J<small>UNK<i><font color=\"red\">BUSTER</font></i></small></strong></center></h1>TCP connection to $rawhost failed: Operation not permitted.\r\n<br></body>\r\n</html>\r\n" },
	{ NULL, NULL }
};

static struct keyvalue goodport[] = {
	{ "junkbuster", "HTTP/1.0 200 Connection established\r\nProxy-Agent: IJ/2.0.2\r\n\r\n" },
	{ NULL, NULL }
};

static struct keyvalue badconnection[] = {
	{ "junkbuster", "HTTP/1.0 400 Invalid header received from browser\r\n\r\n" },
	{ NULL, NULL }
};

static struct keyvalue baddomain[] = {
	{ "junkbuster", "HTTP/1.0 404 Non-existent domain\r\nContent-Type: text/html\r\n\r\n<html>\r\n<head>\r\n<title>Internet Junkbuster: Non-existent domain</title>\r\n</head>\r\n<body bgcolor=\"#f8f8f0\" link=\"#000078\" alink=\"#ff0022\" vlink=\"#787878\">\r\n<h1><center><strong>Internet J<small>UNK<i><font color=\"red\">BUSTER</font></i></small></strong></center></h1>No such domain: $host\r\n</body>\r\n</html>\r\n" },
	{ NULL, NULL }
};

struct keyvalue badconnect[] = {
	{ "junkbuster", "HTTP/1.0 503 Connect failed\r\nContent-Type: text/html\r\n\r\n<html>\r\n<head>\r\n<title>Internet Junkbuster: Connect failed</title>\r\n</head>\r\n<body bgcolor=\"#f8f8f0\" link=\"#000078\" alink=\"#ff0022\" vlink=\"#787878\">\r\n<h1><center><strong>Internet J<small>UNK<i><font color=\"red\">BUSTER</font></i></small></strong></center></h1>TCP connection to $host failed: $reason.\r\n<br></body>\r\n</html>\r\n" },
	{ NULL, NULL }
};

/* Allowed domains */

static struct keyvalue allowedhosts[] = {
    { "www.yahoo.com", "^.*" },
    { "www.google.com", "^.*" },
    { "www.alltheweb.com", "^.*" },
    { "proxychecker.go-mailing.com", "^.*" },
    { "pics.ebay.com", "^.*\\.(jpg|gif|png)$" },
    { "www.ebay.com", "^/(index.html)?$" },
    { "slashdot.org", "^/(index.html|graphics/.*\\.(gif|jpg|png))?$" },
    { "www.gnu.org", "^/(index.html|graphics/.*\\.(gif|jpg|png))?$" },
    { "images.slashdot.org", "^.*\\.(jpg|gif|png)$" },
    { "images2.slashdot.org", "^.*\\.(jpg|gif|png)$" },
    { "www.jstor.org", "^/(index.html|graphics/.*\\.(gif|jpg|png))?$" },
    { "www.sina.com", "^/(index.html|.*\\.(gif|jpg|png))?$" },
    { "www.sina.com.cn", "^/(index.html|.*\\.(gif|jpg|png))?$" },
    { "image.sina.com.cn", "^.*\\.(jpg|gif|png)$" },
    { "image2.sina.com.cn", "^.*\\.(jpg|gif|png)$" },
    { "www.intel.com", "^/(index.html|.*\\.(gif|jpg|png))?$" },
    { "www.sun.com", "^/(index.html|.*\\.(gif|jpg|png))?$" },
    { "www.biomedcentral.com", "^/(index.html|.*\\.(gif|jpg|png))?$" },
    { "www.sciencedirect.com", "^/(index.html|.*\\.(gif|jpg|png))?$" },
    { "digstream.go.com", "^/digstream/autoupdate.xml$" },
    { "www.ingenta.com", "^/(index.html|.*\\.(gif|jpg|png))?$" },
    { "hacker.org.ru", "^/prxjdg.php$" },
    { "www.hitopee.com", "^/cgi/proxyck.cgi$" },
    { "galg999.clawz.com", "^/etc/prxjdg.cgi$" },
    { "www.sheepdouble.com", "^/cgi-bin/cj.cgi$" },
    { "www.antz-pc-school.com", "^/cgi-bin/test/prxjdg.cgi$" },
    { "www.pe4ati.net", "^/cgi-bin/proxyjudge/prxjdg.cgi$" },
    { "musiclub.com.ru", "^/prxjdg.php$" },
    { "www.motorscreensavers.com", "^/cgi-bin/pxjdg11.cgi$" },
    { "www.zbb.jp", "^/unknown/cgi-bin/prxjdg.cgi$" },
    { "www.clickingagent.com", "^/proxycheck.php" },
    { "clickingagent.com", "^/proxycheck.php" },
    { "gjc00.vip.533.net", "^/ip.cgi$" },
    { "www.ebuysearch.com", "^/cgi-bin/ip.cgi$" },
    { "www.exone.net", "^/pj123.cgi$" },
    { "umsky.com", "^/prx.php$" },
    { "www.loomsoft.com", "^/proxycheck/proxyjudge.cgi$" },
    { "www21.big.or.jp", "^/%7Emana_/prxjdg.cgi$" },
    { "www.search591.com", "^/prx.php" },
    { NULL, NULL }
};

#endif /* _PROXY_MESSAGES_H_ */
