#!/bin/bash
#
# by Fabian Bieker <fabian.bieker@web.de>
#

. scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

SERVICE="exchange/IMAP"
HOST="bps-pc9"

login="false"
mail=`head -c 2 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -c 1`

my_start

echo "* OK Microsoft Exchange 2000 IMAP4rev1 server version 6.0.6249.0 ($HOST.$DOMAIN) ready."

while read name; do

	# remove control-characters
	name=`echo "$name" | sed s/[[:cntrl:]]//g`

	echo "$name" >> $LOG

	#name=`echo "$name" | gawk '{print toupper($0);}'` 
	cmd=`echo "$name" | grep -i "[A-Z0-9\.][A-Z0-9\.]* [A-Z][A-Z]*"`

	if [ -z "$cmd" ]; then
		echo "* BAD Invalid tag"
	else 
		id=`echo $cmd | gawk '{print $1;}'`
		param1=`echo $cmd | gawk '{print $3;}'`
		param2=`echo $cmd | gawk '{print $4;}'`
		cmd=`echo $cmd | gawk '{print toupper($2);}'`
		#echo ":$id:$cmd:$param1:$param2:"

		case $cmd in
		LOGIN)
			if [ -n "$param1" -a -n "$param2" ]; then
				rand=`head -c 3 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -c 1`
				if [ $rand -eq 1 -o $rand -eq 2 ]; then	
					login="true"
					echo "$id OK User logged in"
				else 
					login="false"
					echo "$id NO Logon failure: unknown user name or bad password."
				fi
			else
				echo "$id BAD Protocol Error: \"Expected SPACE not found\"."
			fi
		;;
		LOGOUT)
			echo "* BYE Microsoft Exchange 2000 IMAP4rev1 server version 6.0.6249.0 signing off."
			echo "$id OK LOGOUT completed."
			my_stop
		;;
		CAPABILITY)
			echo -n "* CAPABILITY IMAP4 IMAP4rev1 IDLE LOGIN-REFERRALS MAILBOX-REFERRALS "
			echo "NAMESPACE LITERAL+ UIDPLUS CHILDREN AUTH=NTLM"
			echo "$id OK CAPABILITY completed."
		;;
		LIST)
			if [ "$login" == "true" ]; then
				echo "* LIST (\\Noselect) $parm1 $parm2"
				echo "$id OK LIST Completed"
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		STATUS)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" -a -n "$param2" ]; then
					rand=`head -c 2 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -n 1`
					echo "* STATUS $parm1 (MESSAGES $rand)"
					echo "$id OK STATUS Completed"
				else 
					echo "$id BAD Missing required argument to Status"
				fi
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		SELECT)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" ]; then
					rand=`head -c 15 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -n 1`
					echo "* FLAGS (\Answered \Flagged \Draft \Deleted \Seen)"
					echo "* OK [PERMANENTFLAGS (\Answered \Flagged \Draft \Deleted \Seen \*)]"
					echo "* $mail EXISTS"
					echo "* 0 RECENT"
					echo "* OK [UIDVALIDITY $rand]"
					echo "$id OK [READ-WRITE] Completed"
					mail=`head -c 2 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -c 1`
				else
					echo "$id BAD Missing required argument to Select"
				fi
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		EXAMINE)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" ]; then
					rand=`head -c 15 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -n 1`
					echo "* FLAGS (\Answered \Flagged \Draft \Deleted \Seen)"
					echo "* $mail EXISTS"
					echo "* 0 RECENT"
					echo "* OK [UIDVALIDITY $rand]"
					echo "* OK [PERMANENTFLAGS (\Answered \Flagged \Draft \Deleted \Seen \*)]"
					echo "$id OK [READ-ONLY] Completed"
					mail=`head -c 2 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -c 1`
				else
					echo "$id BAD Missing required argument to Examine"
				fi
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		SUBSCRIBE)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" ]; then
					echo "$id OK SUBSCRIBE Completed"
				else
					echo "$id BAD Missing required argument to Subscribe"
				fi
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		FETCH)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" -a "$param2" ]; then
					rand=`head -c 2 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -c 1`
					for i in `seq 1 $rand`; do
						echo "* NO Disk IO Error"
					done
					echo "$id OK FETCH Completed"
				else
					echo "$id BAD Missing required argument to Fetch"
				fi
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		STORE)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" -a "$param2" ]; then
					echo "$id OK STORE Completed"
				else
					echo "$id BAD Missing required argument to Store"
				fi
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		COPY)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" -a "$param2" ]; then
					echo "$id OK COPY Completed"
				else
					echo "$id BAD Missing required argument to Copy"
				fi
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		APPEND)
			if [ "$login" == "true" ]; then
				sleep 5
				echo "$id OK APPEND Completed"
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		EXPUNGE)
			if [ "$login" == "true" ]; then
				rand=`head -c 2 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -n 1`
				echo "* $rand EXPUNGE"
				rand=`head -c 2 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -n 1`
				echo "* $rand EXPUNGE"
				rand=`head -c 2 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -n 1`
				echo "* $rand EXPUNGE"
				echo "$id OK EXPUNGE Completed"
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		SEARCH)
			if [ "$login" == "true" ]; then
				echo "$id BAD Protocol Error: \"Invalid key supplied in the SEARCH command\"."
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		CREATE)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" ]; then
					echo "$id OK CREATE Completed"
				else
					echo "$id BAD Protocol Error: \"Expected SPACE not found\"."
				fi
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		DELETE)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" ]; then
					echo "$id OK DELETE Completed"
				else
					echo "$id BAD Protocol Error: \"Expected SPACE not found\"."
				fi
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		RENAME)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" -a "$param2" ]; then
					echo "$id OK RENAME Completed"
				else
					echo "$id BAD Protocol Error: \"Expected SPACE not found\"."
				fi
			else
				echo "$id BAD CHECK command received in invalid state."
			fi
		;;
		NOOP)
			echo "$id OK NOOP completed." 
		;;
		CHECK)
			echo "$id BAD CHECK command received in invalid state."
		;;
		*)
			echo "$id BAD Protocol Error: \"Unidentifiable command specified\"."
		;;
		esac
	fi
done

my_stop
