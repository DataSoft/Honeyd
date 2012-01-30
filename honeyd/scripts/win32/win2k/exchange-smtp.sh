#!/bin/bash

# 
# SMTP (Exchange 2000) Honeypot-Script intended for use with 
# Honeyd from Niels Provos
# -> http://www.citi.umich.edu/u/provos/honeyd/
# 
# Author: Fabian Bieker <fabian.bieker@web.de>
# Based on: Maik Ellingers Sendmail Script
# Last modified: 08/03/2003
# Version: 0.0.8
# 
# Changelog: 
# 0.0.1: 
#

. scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

SERVICE="exchange/SMTP"
HOST="bps-pc9"

MAILFROM="err"
EHELO="no"
RCPTTO="err"
DATA="err"

my_start
echo -e "220 $HOST.$DOMAIN Microsoft ESMTP MAIL Service, Version: 5.0.2195.5329 ready at  $DATE"
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
	incmd_nocase=`echo $incmd | gawk '{print toupper($0);}'`
	#echo $incmd_nocase
	case $incmd_nocase in
	    QUIT* )	
			echo -e "221 2.0.0 $HOST.$DOMAIN Service closing transmission channel\r"
            my_stop
		;;
	    RSET* )	
		echo -e "250 2.0.0 Resetting\r"
		;;
	    HELP* )
		echo -e "214-This server supports the following commands:\r"
		echo -e "214 HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH TURN ATRN ETRN BDAT VRFY\r"
		;;
	    HELO* )
		  EHELO="ok"
		  echo "250 $HOST.$DOMAIN Hello [$1]"
		;;
	    EHLO* )
		  EHELO="ok"
		  echo -e "250-$HOST.$DOMAIN Hello [$1]\r"
		  echo -e "250-TURN\r\n250-ATRN\r\n250-SIZE\r\n250-ETRN\r\n250-PIPELINING\r\n250-DSN\r"
		  echo -e "250-ENHANCEDSTATUSCODES\r\n250-8bitmime\r\n250-BINARYMIME\r\n250-CHUNKING\r"
		  echo -e "250-VRFY\r\n250-X-EXPS GSSAPI NTLM LOGIN\r\n250-X-EXPS=LOGIN\r"
		  echo -e "250-AUTH GSSAPI NTLM LOGIN\r\n250-AUTH=LOGIN\r\n250-X-LINK2STATE\r\n250-XEXCH50}\r"
		  echo -e "250 OK\r"
		;;
	    MAIL* )
		haveFROM=`echo $parm1 | gawk -F: '{print toupper($1);}'`
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
		  echo -e "501 5.5.4 Invalid arguments\r"
		fi
		;;
	    RCPT* )
		haveTO=`echo $parm1 | gawk -F: '{print toupper($1);}'`
		if [ "$haveTO" == "TO"  ]; then
			if [ "$MAILFROM" == "ok"  ]; then 
	    		if [ `echo "$incmd$parm1$parm2" | grep '<.*>' 2>&1 >/dev/null && echo 1` ]; then
				    RCPTTO="ok"
				    #echo "553 sorry, that domain isn't in my list of allowed rcpthosts (#6.7.1)"
					echo -e "250 2.1.5 $parm2 $parm3 $parm4\r"
				else
	  				echo -e "501 5.5.4 Invalid arguments\r"
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
			echo -e "354 Start mail input; end with <CRLF>.<CRLF>\r"
		;;
		. )
			DATA="err"	
			TMPID=`head -c 15 /dev/urandom | hexdump | sed -e 's/[ 0]//g' | head -n 1`
			echo -e "250 2.6.0 <$TMPID@$HOST.$DOMAIN> Queued mail for delivery\r"
		;;
		VRFY*)
			if [ -z $parm1 ]; then
				echo -e "501 5.5.4 Argument missing\r"
			else
				echo -e "252 2.1.5 Cannot VRFY user, but will take message for <$parm1@$domain>\r"
			fi
		;;
		ETRN*)
			echo -e "250 2.0.0 Queuing for $parm1 started\r"
		;;
	    STARTTLS* )
		echo -e "554 5.7.3 Unable to initialize security subsystem\r"
		;;
	    NOOP* )
		echo -e "250 2.0.0 OK\r"
		;;
	    AUTH* )
		echo -e "503 AUTH mechanism not available\r"
		;;
	    * )
		if [ $DATA != "ok" ]; then
			echo -e "500 5.3.3 Command unrecognized: \"$incmd\"\r"
		fi
		;;
	esac
	echo "$incmd $parm1 $parm2 $parm3 $parm4 $parm5" >> $LOG
done

my_stop
