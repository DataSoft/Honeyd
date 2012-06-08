#!/bin/bash
#
# by Fabian Bieker <fabian.bieker@web.de>
# modified by DataSoft Corporation

. scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

STRINGSFILE=$5
VERSION=`perl -nle '/SQUID_VERSION (.*)/ and print $1' < $STRINGSFILE`


SERVICE="squid/PROXY"
HOST="serv"
LOG="/var/log/honeyd/web.log"

REQUEST=""

my_start

while read name; do
	
	# remove control-characters
	name=`echo $name | sed s/[[:cntrl:]]//g`

	LINE=`echo "$name" | egrep -i "[a-z:]"`
	if [ -z "$LINE" ]
	then
		break
	fi
	echo "$name" >> $LOG

	NEWREQUEST=`echo "$name" | egrep -i "(GET|POST) [a-z0-9\./:-\?]+ HTTP/1\.(0|1)"`
	if [ ! -z "$NEWREQUEST" ] ; then
		REQUEST="GETPOST"
	fi

	NEWREQUEST=`echo "$name" | egrep -i "CONNECT [a-z0-9\./:-\?]+"`
	if [ ! -z "$NEWREQUEST" ] ; then
		REQUEST="CONNECT"
	fi
done


if [ -z "$REQUEST" ] ; then
	cat << _eof_
HTTP/1.0 400 Bad Request
Server: $VERSION
Mime-Version: 1.0
Date: $DATE 
Content-Type: text/html
Expires: $DATE 
X-Squid-Error: ERR_INVALID_REQ 0
X-Cache: MISS from $HOST.$DOMAIN 
X-Cache-Lookup: NONE from $HOST.$DOMAIN:$2
Proxy-Connection: close

<HTML><HEAD>
<TITLE>ERROR: The requested URL could not be retrieved</TITLE>
</HEAD><BODY>
<H1>ERROR</H1>
<H2>The requested URL could not be retrieved</H2>
<HR>
<P>
While trying to process the request:
<PRE>
$name
</PRE>
<P>
The following error was encountered:
<UL>
<LI>
<STRONG>
Invalid Request
</STRONG>
</UL>

<P>
Some aspect of the HTTP Request is invalid.  Possible problems:
<UL>
<LI>Missing or unknown request method
<LI>Missing URL
<LI>Missing HTTP Identifier (HTTP/1.0)
<LI>Request is too large
<LI>Content-Length missing for POST or PUT requests
<LI>Illegal character in hostname; underscores are not allowed
</UL>
<P>Your cache administrator is <A HREF="mailto:webcache@$HOST.DOMAIN">webcache@$HOST.$DOMAIN</A>.
_eof_
	my_stop
fi

sleep 5
cat << _eof_
HTTP/1.0 400 CONNECT_FAIL 
Server: $VERSION
Mime-Version: 1.0
Date: $DATE 
Content-Type: text/html
Expires: $DATE 
X-Squid-Error: ERR_CONNECT_FAIL 0
X-Cache: MISS from $HOST.$DOMAIN 
X-Cache-Lookup: NONE from $HOST.$DOMAIN:$2
Proxy-Connection: close

<HTML><HEAD>
<TITLE>ERROR: The requested URL could not be retrieved</TITLE>
</HEAD><BODY>
<H1>ERROR</H1>
<H2>The requested URL could not be retrieved</H2>
<HR>
<P>
While trying to retrieve the URL:
<A HREF="$name">$name</A>
<P>
The following error was encountered:
<UL>
<LI>
<STRONG>
Connection Failed
</STRONG>
</UL>

<P>
The system returned:
<PRE><I>CONNECTION TIMEOUT</I></PRE>

<P>
The remote host or network may be down.  Please try the request again.
<P>Your cache administrator is <A HREF="mailto:webcache@$HOST.DOMAIN">webcache@$HOST.$DOMAIN</A>.
_eof_

my_stop
