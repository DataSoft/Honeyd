#!/bin/bash
# 
# Author: Fabian Bieker <fabian.bieker@web.de>
# Last modified: 24/06/2002
# Version: 0.0.1
# 
# Changelog: 
# 
# 0.0.1: initial release
# 
#
# $1: srcip, $2: srcport, $3: dstip, $4: dstport
#

. scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

SERVICE="exchange/POP3"
HOST="bps-pc9"

AUTH="no"
PASS="no"

my_start
echo -e "+OK Microsoft Exchange 2000 POP3 server version 6.0.6249.0 ($HOST.$DOMAIN) ready.\r"
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
		echo -e "+OK Microsoft Exchange 2000 POP3 server version 6.0.6249.0 signing off.\r"
                exit 0;;
	    HELP* )
		echo -e "-ERR No help.\r"
		;;
	    USER* )
		parm1_nocase=`echo $parm1 | gawk '{print toupper($0);}'`
		if [ "$parm1_nocase" == "" ]
		then
		  echo -e "-ERR Too few arguments for the user command.\r"
		else
		  echo -e "+OK Password required for $parm1.\r"
                  AUTH=$parm1
		fi
		;;
	    PASS* )
		rand=`head -c 3 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -c 1`
		if [ $rand -eq 1 -o $rand -eq 2 ]; then	
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
		echo -e "+OK 1 1348\r"
		;;
	    NOOP* )
		echo -e "+OK\r"
		;;
	    RSET* )
		echo -e "+OK\r"
		;;
	    * )
		echo -e "500 '$incmd': command not understood.\r"
		;;
	esac
	echo -e "$incmd $parm1 $parm2 $parm3 $parm4 $parm5" >> $LOG
done

my_stop
