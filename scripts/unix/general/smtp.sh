#!/bin/bash

# 
# SMTP (Sendmail) Honeypot-Script intended for use with 
# Honeyd from Niels Provos
# -> http://www.citi.umich.edu/u/provos/honeyd/
# 
# Author: Maik Ellinger
# Last modified: 17/06/2002
# Version: 0.0.8
# 
# Changelog: 
# 0.0.7: - bugfix: sending correct CR/LF -> ToDO: correct all echo where necessary
#	 - bugfix: handling of EHLO now clean
#	 - bugfix: RCPT command response
#
# 0.0.4: - bugfix: suppress interpreting of control-characters
# 

#set -x -v
DATE=`date`
host=`hostname`
domain=`dnsdomainname`
log=/tmp/honeyd/smtp-$1.log
MAILFROM="err"
EHELO="no"
RCPTTO="err"
echo "$DATE: SMTP started from $1 Port $2" >> $log
echo -e "220 $host.$domain ESMTP Sendmail 8.12.2/8.12.2/SuSE Linux 0.6; $DATE\r"
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
		echo "220 2.0.0 $host.$domain closing connection"
                exit 0;;
	    RSET* )	
		echo "250 2.0.0 Reset state"
		;;
	    HELP* )
		echo "214-2.0.0 This is sendmail version 8,12,2"
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
		  echo "250 $host.$domain Hello $parm1[$1], pleased to meet you"
		else
		  echo "501 5.0.0 HELO requires domain address"
		fi
		;;
	    EHLO* )
		if [ -n "$parm1" ]
		then
		  EHELO="ok"
		  echo -e "250-$host.$domain Hello $parm1[$1], pleased to meet you\r"
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
		haveFROM=`echo $parm1 | awk '{print toupper($0);}'`
		if [ "$haveFROM" == "FROM:" ]
		then
	    			if [ -n "$parm2" ]
				then
				    MAILFROM="ok"
    				    echo "250 2.1.0 $parm2 $parm3 $parm4... Sender ok"
				else
				    echo "501 5.5.2 Syntax error in parameters scanning \"$parm2\""
				    MAILFROM="err"
				fi
		else
		  echo "501 5.5.2 Syntax error in parameters scanning \"\""
		fi
		;;
	    RCPT* )
		#echo $MAILFROM
		if [ "$MAILFROM" == "ok"  ]
		then
			haveTO=`echo $parm1 | awk '{print toupper($0);}'`
			if [ "$haveTO" == "TO:"  ]
			then
	    			if [ -n "$parm2" ]
				then
				    RCPTTO="ok"
				    echo "553 sorry, that domain isn't in my list of allowed rcpthosts (#6.7.1)"
				else
				    echo "501 5.5.2 Syntax error in parameters scanning \"\""
				    RCPTTO="err"
				fi
			fi
		else
		  echo "503 5.0.0 Need MAIL before RCPT"
		fi
		;;
	    STARTTLS* )
		echo "454 4.3.3 TLS not available after start"
		;;
	    NOOP* )
		echo "250 2.0.0 OK"
		;;
	    AUTH* )
		echo "503 AUTH mechanism not available"
		;;
	    * )
		echo "500 5.5.1 Command unrecognized: \"$incmd\""
		;;
	esac
	echo "$incmd $parm1 $parm2 $parm3 $parm4 $parm5" >> $log
done

