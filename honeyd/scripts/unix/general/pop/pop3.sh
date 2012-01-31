#!/bin/bash
# 
# POP3 Honeypot-Script intended for use with 
# Honeyd from Niels Provos 
# -> http://www.citi.umich.edu/u/provos/honeyd/
# 
# Author: Maik Ellinger
# Last modified: 24/06/2002
# Version: 0.0.1
# 
# Changelog: 
# 
# 0.0.1: initial release
# 

#set -x -v
DATE=`date`
host=`hostname`
domain=`dnsdomainname`
log=/tmp/honeyd/pop3-$1.log
AUTH="no"
PASS="no"
LOGINOK="yes"    # give to all logins a "+OK Mailbox open, 3 messages" back (no/yes)
echo "$DATE: POP3 started from $1 Port $2" >> $log
echo -e "+OK QPOP (version 2.53) at $host.$domain starting.\r"
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

	if [ "$AUTH" == "no" ]
        then
	    if [ "$incmd_nocase" != "USER" ]
            then 
		if [ "$incmd_nocase" != "QUIT" ]
    		then 
        	    echo -e "-ERR Unknown command: \"$incmd\"\r"
		    continue
		fi
	    fi
	fi

	case $incmd_nocase in

	    QUIT* )	
		echo -e "+OK Pop serrver at $host.$domain signing off.\r"
                exit 0;;
	    HELP* )
		echo -e "-ERR No help.\r"
		;;
	    USER* )
		parm1_nocase=`echo $parm1 | awk '{print toupper($0);}'`
		if [ "$parm1_nocase" == "" ]
		then
		  echo -e "-ERR Too few arguments for the user command.\r"
		else
		  echo -e "+OK Password required for $parm1.\r"
                  AUTH=$parm1
		fi
		;;
	    PASS* )
		if [ "$LOGINOK" == "yes" ]
		then
            	    PASS=$parm1
		    echo -e "+OK Mailbox open, 1 messages\r"
		else
		    echo -e "-ERR Password supplied for \"$AUTH\" is incorrect.\r"
		fi
		;;
	    LIST* )
		echo -e "+OK Mailbox scan listing follows\r"
		echo -e "1 1340\r"
		echo -e ".\r"
		;;
	    DELE* )
		echo -e "-ERR message $parm1 already deleted\r"
		;;
	    RETR* )
		if [ "$parm1" == "1" ]
		then
		    echo -e "+OK 1340 octets\r"
		else
		    echo -e "-ERR No such message\r"
		fi
		;;
	    STAT* )
		echo -e "+OK 0 0\r"
		;;
	    NOOP* )
		echo -e "+OK No-op to you too!\r"
		;;
	    RSET* )
		echo -e "+OK Reset state\r"
		;;
	    * )
		echo -e "500 '$incmd': command not understood.\r"
		;;
	esac
	echo -e "$incmd $parm1 $parm2 $parm3 $parm4 $parm5" >> $log
done

