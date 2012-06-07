#!/bin/sh
REQUEST=""
while read name
do
	LINE=`echo "$name" | egrep -i "[a-z:]"`
	if [ -z "$LINE" ]
	then
		break
	fi
	echo "$name" >> /usr/share/nova/Logs/scripts/iis.log
	NEWREQUEST=`echo "$name" | grep "GET .scripts.*cmd.exe.*dir.* HTTP/1.0"`
	if [ ! -z "$NEWREQUEST" ] ; then
		REQUEST=$NEWREQUEST
	fi
done

if [ -z "$REQUEST" ] ; then
	cat << _eof_
HTTP/1.1 404 NOT FOUND
Server: Microsoft-IIS/5.0
P3P: CP='ALL IND DSP COR ADM CONo CUR CUSo IVAo IVDo PSA PSD TAI TELo OUR SAMo CNT COM INT NAV ONL PHY PRE PUR UNI'
Content-Location: http://cpmsftwbw27/default.htm
Date: Thu, 04 Apr 2002 06:42:18 GMT
Content-Type: text/html
Accept-Ranges: bytes

<html><title>You are in Error</title>
<body>
<h1>You are in Error</h1>
O strange and inconceivable thing! We did not really die, we were not really buried, we were not really crucified and raised again, but our imitation was but a figure, while our salvation is in reality. Christ was actually crucified, and actually buried, and truly rose again; and all these things have been vouchsafed to us, that we, by imitation communicating in His sufferings, might gain salvation in reality. O surpassing loving-kindness! Christ received the nails in His undefiled hands and feet, and endured anguish; while to me without suffering or toil, by the fellowship of His pain He vouchsafed salvation.
<p>
St. Cyril of Jerusalem, On the Christian Sacraments.
</body>
</html>
_eof_
	exit 0
fi

DATE=`date`
cat << _eof_
HTTP/1.0 200 OK
Date: $DATE
Server: Microsoft-IIS/5.0
Connection: close
Content-Type: text/plain


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
