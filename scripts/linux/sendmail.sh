#!/bin/bash

# 
# SMTP (Sendmail) Honeypot-Script intended for use with 
# Honeyd from Niels Provos
# -> http://www.citi.umich.edu/u/provos/honeyd/
# 
# Author: Maik Ellinger
# 
# Changelog: 
# 0.0.7: - bugfix: sending correct CR/LF -> ToDO: correct all echo where necessary
#	 - bugfix: handling of EHLO now clean
#	 - bugfix: RCPT command response
#
# 0.0.4: - bugfix: suppress interpreting of control-characters
# 
#
# $1: srcip, $2: srcport, $3: dstip, $4: dstport
#
# modified by Fabian Bieker <fabian.bieker@web.de>
# modified by DataSoft Corporation
#

. scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

STRINGSFILE=$5
VERSION=`perl -nle '/SENDMAIL_VERSION (.*)/ and print $1' < $STRINGSFILE`


SERVICE="sendmail/SMTP"
HOST="serv"

MAILFROM="err"
EHELO="no"
RCPTTO="err"

my_start
echo -e "220 $HOST.$DOMAIN ESMTP $VERSION; $DATE\r" 

while read incmd parm1 parm2 parm3 parm4 parm5
do
	# remove control-characters
	incmd=`echo $incmd | sed s/[[:cntrl:]]//g`
	parm1=`echo $parm1 | sed s/[[:cntrl:]]//g`
	parm2=`echo $parm2 | sed s/[[:cntrl:]]//g`
	parm3=`echo $parm3 | sed s/[[:cntrl:]]//g`
	parm4=`echo $parm4 | sed s/[[:cntrl:]]//g`
	parm5=`echo $parm5 | sed s/[[:cntrl:]]//g`

	# convert to upper-case
	incmd_nocase=`echo $incmd | awk '{print toupper($0);}'`
	#echo $incmd_nocase
	case $incmd_nocase in
	    QUIT* )	
			echo -e "220 2.0.0 $HOST.$DOMAIN closing connection\r"
            my_stop
		;;
	    RSET* )	
		echo -e "250 2.0.0 Reset state\r"
		;;
	    HELP* )
		echo "214-2.0.0 This is $VERSION"
		echo "214-2.0.0 Topics:"
		echo "214-2.0.0       HELO    EHLO    MAIL    RCPT    DATA"
		echo "214-2.0.0       RSET    NOOP    QUIT    HELP    VRFY"
		echo "214-2.0.0       EXPN    VERB    ETRN    DSN     AUTH"
		echo "214-2.0.0       STARTTLS"
		echo "214-2.0.0 For more info use \"HELP <topic>\"."
		echo "214-2.0.0 To report bugs in the implementation send email to"
		echo "214-2.0.0       sendmail-bugs@sendmail.org."
		echo "214-2.0.0 For local information send email to Postmaster at your site."
		echo "214 2.0.0 End of HELP info"
		;;
	    HELO* )
		if [ -n "$parm1" ]
		then
		  EHELO="ok"
		  echo "250 $HOST.$DOMAIN Hello $parm1[$1], pleased to meet you"
		else
		  echo "501 5.0.0 HELO requires domain address"
		fi
		;;
	    EHLO* )
		if [ -n "$parm1" ]
		then
		  EHELO="ok"
		  echo -e "250-$HOST.$DOMAIN Hello $parm1[$1], pleased to meet you\r"
		  echo -e "250-ENHANCEDSTATUSCODES\r"
           	  echo -e "250-PIPELINING\r"
		  echo -e "250-8BITMIME\r"
		  echo -e "250-SIZE\r"
		  echo -e "250-DSN\r"
		  echo -e "250-ETRN\r"
		  echo -e "250-DELIVERYBY\r"
		  echo -e "250 HELP\r"
		else
		  echo -e "501 5.0.0 EHLO requires domain address\r"
		fi
		;;
	    MAIL* )
		haveFROM=`echo $parm1 | awk -F: '{print toupper($1);}'`
		if [ "$haveFROM" == "FROM" ]
		then
	    		if [ `echo "$incmd$parm1$parm2" | grep '<.*>' 2>&1 >/dev/null && echo 1` ]; then
				    MAILFROM="ok"
    				echo -e "250 2.1.0 $parm2 $parm3 $parm4... Sender ok\r"
				else
				    echo -e "501 5.5.2 Syntax error in parameters scanning \"$parm2\"\r"
				    MAILFROM="err"
				fi
		else
			echo -e "500 5.5.1 Command unrecognized: \"$incmd $parm1\"\r"
		fi
		;;
	    RCPT* )
		haveTO=`echo $parm1 | awk -F: '{print toupper($1);}'`
		if [ "$haveTO" == "TO"  ]; then
			if [ "$MAILFROM" == "ok"  ]; then 
	    		if [ `echo "$incmd$parm1$parm2" | grep '<.*>' 2>&1 >/dev/null && echo 1` ]; then
				    RCPTTO="ok"
				    #echo "553 sorry, that domain isn't in my list of allowed rcpthosts (#6.7.1)"
					echo -e "250 2.1.5 $parm2 $parm3 $parm4... Recipient ok\r"
				else
				    echo -e "501 5.5.2 Syntax error in parameters scanning \"$parm2\"\r"
				    RCPTTO="err"
				fi
			else
		  		echo "503 5.0.0 Need MAIL before RCPT"
			fi
		else
			echo -e "500 5.5.1 Command unrecognized: \"$incmd $parm1\"\r"
		fi
		;;
		DATA* )
			DATA="ok"
			echo -e "354 Enter mail, end with "." on a line by itself\r"
		;;
		. )
			DATA="err"	
			TMPID=`head -c 10 /dev/urandom | hexdump | sed -e 's/[ 0]//g' | head -n 1`
			echo -e "250 2.0.0 $TMPID Message accepted for delivery\r"
		;;
		VRFY*|EXPN*)
			echo -e "550 5.1.1 $parm1... User unknown\r"
		;;
		ETRN*)
			echo -e "250 2.0.0 Queuing for $parm1 started\r"
		;;
	    STARTTLS* )
		echo -e "454 4.3.3 TLS not available after start\r"
		;;
	    NOOP* )
		echo -e "250 2.0.0 OK\r"
		;;
	    AUTH* )
		echo -e "503 AUTH mechanism not available\r"
		;;
	    * )
		if [ "$DATA" != "ok" ]; then
			echo -e "500 5.5.1 Command unrecognized: \"$incmd\"\r"
		fi
		;;
	esac
	echo "$incmd $parm1 $parm2 $parm3 $parm4 $parm5" >> $LOG
done

my_stop
