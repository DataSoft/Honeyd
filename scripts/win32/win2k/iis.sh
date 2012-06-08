#!/bin/sh
#
# by Fabian Bieker <fabian.bieker@web.de>
#

. scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

SERVICE="IIS/HTTP"
HOST="bps-pc9"
LOG="/var/log/honeyd/web.log"

VERSION="Microsoft-IIS/5.0"

REQUEST=""

rand1=`head -c 100 /dev/urandom | hexdump | sed -e 's/[0-9 ]//g' | awk '{print toupper($0);}' | head -c 8 | head -n 1`
rand2=`head -c 300 /dev/urandom | hexdump | sed -e 's/[0-9 ]//g' | awk '{print toupper($0);}' | head -c 20 | head -n 1`

my_start

read req1

# remove control-characters
name=`echo $req1 | sed s/[[:cntrl:]]//g`

echo "$req1" >> $LOG

NEWREQUEST=`echo "$req1" | grep -E "GET .* HTTP/1.(0|1)"`
if [ -n "$NEWREQUEST" ] ; then
	REQUEST="GET"
fi

NEWREQUEST=`echo "$req1" | grep -E "GET (/|/?index.html?|/?index.(a|j)sp) HTTP/1.(0|1)"`
if [ -n "$NEWREQUEST" ] ; then
	REQUEST="GET_/"
fi

NEWREQUEST=`echo "$req1" | grep -E "GET .scripts.*cmd.exe.*dir.* HTTP/1.(0|1)"`
if [ -n "$NEWREQUEST" ] ; then
	REQUEST="cmd_dir"
fi

NEWREQUEST=`echo "$req1" | grep -E "HEAD .* HTTP/1.(0|1)"`
if [ -n "$NEWREQUEST" ] ; then
	REQUEST="HEAD"
fi

while read name
do
	
	# remove control-characters
	name=`echo $name | sed s/[[:cntrl:]]//g`

	LINE=`echo "$name" | egrep -i "[a-z:]"`
	if [ -z "$LINE" ]
	then
		break
	fi

	echo "$name" >> $LOG

done

case $REQUEST in
  GET_/)
	cat << _eof_
HTTP/1.1 200 OK
Server: $VERSION
P3P: CP='ALL IND DSP COR ADM CONo CUR CUSo IVAo IVDo PSA PSD TAI TELo OUR SAMo CNT COM INT NAV ONL PHY PRE PUR UNI'
Date: $DATE 
Content-Type: text/html
Connection: close
Accept-Ranges: bytes
Set-Cookie: isHuman=Y; path=/
Set-Cookie: visits=1; expires=$date; path=/
Set-Cookie: ASPSESSIONID$rand1=$rand2; path=/
Expires: $DATE
Cache-control: private

<html><title>Under Heavy Construction</title>
<body>
<br><br>
<h1>Site is under Heavy Construction</h1>
<b>coming soon...<b>
</body>
</html>
_eof_
  ;;
  GET)
	cat << _eof_
HTTP/1.1 302 Object moved
Server: $VERSION
P3P: CP='ALL IND DSP COR ADM CONo CUR CUSo IVAo IVDo PSA PSD TAI TELo OUR SAMo CNT COM INT NAV ONL PHY PRE PUR UNI'
Date: $DATE 
Content-Type: text/html
Connection: close
Accept-Ranges: bytes
Set-Cookie: isHuman=Y; path=/
Set-Cookie: visits=1; expires=$date; path=/
Set-Cookie: ASPSESSIONID$rand1=$rand2; path=/
Expires: $DATE
Cache-control: private

<head><title>Object moved</title></head>
<body><h1>Object Moved</h1>This object may be found <a HREF="http://$HOST.$DOMAIN/">here</a>.</body>
_eof_
  ;;
  HEAD)
	cat << _eof_
HTTP/1.1 200 OK
Server: $VERSION
P3P: CP='ALL IND DSP COR ADM CONo CUR CUSo IVAo IVDo PSA PSD TAI TELo OUR SAMo CNT COM INT NAV ONL PHY PRE PUR UNI'
Date: $DATE 
Content-Type: text/html
Connection: close
Content-Length: 31675
Content-Type: text/html
Expires: $DATE
Accept-Ranges: bytes

_eof_
  ;;

  cmd_dir)
	cat << _eof_
HTTP/1.0 200 OK
Server: $VERSION
P3P: CP='ALL IND DSP COR ADM CONo CUR CUSo IVAo IVDo PSA PSD TAI TELo OUR SAMo CNT COM INT NAV ONL PHY PRE PUR UNI'
Date: $DATE
Connection: close
Content-Type: text/plain
Expires: $DATE
Cache-control: private


 Volume in drive C is Webserver      
 Volume Serial Number is 3421-07F5
 Directory of C:\inetpub

01-20-02   3:58a      <DIR>          .
08-21-01   9:12a      <DIR>          ..
08-21-01  11:28a      <DIR>          AdminScripts
08-21-01   6:43p      <DIR>          ftproot
07-09-00  12:04a      <DIR>          iissamples
07-03-00   2:09a      <DIR>          mailroot
07-16-00   3:49p      <DIR>          Scripts
07-09-00   3:10p      <DIR>          webpub
07-16-00   4:43p      <DIR>          wwwroot
             0 file(s)              0 bytes
            20 dir(s)     290,897,920 bytes free
_eof_
  ;;
  *)
	cat << _eof_
HTTP/1.1 400 Bad Request
Server: $VERSION
Date: $DATE
Content-Type: text/html
Content-Length: 87

<html><head><title>Error</title></head><body>The parameter is incorrect. </body></html>Connection closed by foreign host.
_eof_
  ;;
esac

my_stop
