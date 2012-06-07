#!/bin/bash
#
# $1: srcip, $2: srcport, $3: dstip, $4: dstport, $5 configFile
#
# modified by Fabian Bieker <fabian.bieker@web.de>
# modified by DataSoft Corporation

. scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

STRINGSFILE=$5
VERSION=`perl -nle '/CYRUS_VERSION (.*)/ and print $1' < $STRINGSFILE`

SERVICE="cyrus/IMAP"
HOST="serv"

login="false"
mail=`head -c 2 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -c 1`

my_start
echo -e "* OK $HOST $VERSION server ready"

while read name; do

	# remove control-characters
	name=`echo "$name" | sed s/[[:cntrl:]]//g`

	echo "$name" >> $LOG

	#name=`echo "$name" | awk '{print toupper($0);}'` 
	cmd=`echo "$name" | grep -i "[A-Z0-9\.][A-Z0-9\.]* [A-Z][A-Z]*"`

	if [ -z "$cmd" ]; then
		echo "* BAD Invalid tag"
	else 
		id=`echo $cmd | awk '{print $1;}'`
		param1=`echo $cmd | awk '{print $3;}'`
		param2=`echo $cmd | awk '{print $4;}'`
		cmd=`echo $cmd | awk '{print toupper($2);}'`
		#echo ":$id:$cmd:$param1:$param2:"

		case $cmd in
		LOGIN)
			if [ -n "$param1" -a -n "$param2" ]; then
				rand=`head -c 2 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -c 1`
				if [ $rand -eq 1 -o $rand -eq 2 ]; then	
					login="true"
					echo "$id OK User logged in"
				else 
					sleep 3
					login="false"
					echo "$id NO Invalid user"
				fi
			else
				echo "$id BAD Missing required argument to Login"
			fi
		;;
		LOGOUT)
			echo "* BYE LOGOUT received"
			my_stop
		;;
		CAPABILITY)
			echo -n "* CAPABILITY IMAP4 IMAP4rev1 ACL QUOTA LITERAL+ NAMESPACE UIDPLUS "
			echo "X-NON-HIERARCHICAL-RENAME NO_ATOMIC_RENAME UNSELECT X-NETSCAPE"
			echo "$id OK completed"
		;;
		LIST)
			if [ "$login" == "true" ]; then
				echo "* LIST (\\Noselect) $parm1 $parm2"
				echo "$id OK Completed"
			else
				echo "$id BAD Please login first"
			fi
		;;
		STATUS)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" -a -n "$param2" ]; then
					rand=`head -c 2 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -n 1`
					echo "* STATUS $parm1 (MESSAGES $rand)"
					echo "$id OK Completed"
				else 
					echo "$id BAD Missing required argument to Status"
				fi
			else
				echo "$id BAD Please login first"
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
				echo "$id BAD Please login first"
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
				echo "$id BAD Please login first"
			fi
		;;
		SUBSCRIBE)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" ]; then
					echo "$id OK Completed"
				else
					echo "$id BAD Missing required argument to Subscribe"
				fi
			else
				echo "$id BAD Please login first"
			fi
		;;
		FETCH)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" -a "$param2" ]; then
					rand=`head -c 2 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -c 1`
					for i in `seq 1 $rand`; do
						echo "* NO Internel Server Error"
					done
					echo "$id OK Completed"
				else
					echo "$id BAD Missing required argument to Fetch"
				fi
			else
				echo "$id BAD Please login first"
			fi
		;;
		STORE)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" -a "$param2" ]; then
					echo "$id OK Completed"
				else
					echo "$id BAD Missing required argument to Store"
				fi
			else
				echo "$id BAD Please login first"
			fi
		;;
		COPY)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" -a "$param2" ]; then
					echo "$id OK Completed"
				else
					echo "$id BAD Missing required argument to Copy"
				fi
			else
				echo "$id BAD Please login first"
			fi
		;;
		APPEND)
			if [ "$login" == "true" ]; then
				sleep 5
				echo "$id OK Completed"
			else
				echo "$id BAD Please login first"
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
				echo "$id OK Completed"
			else
				echo "$id BAD Please login first"
			fi
		;;
		SEARCH)
			if [ "$login" == "true" ]; then
				echo "$id BAD Missing required argument to Search"
			else
				echo "$id BAD Please login first"
			fi
		;;
		MYRIGHTS)
			if [ "$login" == "true" ]; then
				echo "* MYRIGHTS $parm1 lrswipcda"
				echo "$id OK Completed"
			else
				echo "$id BAD Please login first"
			fi
		;;
		CREATE)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" ]; then
					echo "$id OK Completed"
				else
					echo "$id BAD Missing required argument to Create"
				fi
			else
				echo "$id BAD Please login first"
			fi
		;;
		DELETE)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" ]; then
					echo "$id OK Completed"
				else
					echo "$id BAD Missing required argument to Delete"
				fi
			else
				echo "$id BAD Please login first"
			fi
		;;
		RENAME)
			if [ "$login" == "true" ]; then
				if [ -n "$param1" -a "$param2" ]; then
					echo "$id OK Completed"
				else
					echo "$id BAD Missing required argument to Rename"
				fi
			else
				echo "$id BAD Please login first"
			fi
		;;
		NOOP|CHECK)
			echo "$id OK Completed"
		;;
		*)
			echo "$id BAD Unrecognized command"
		;;
		esac
	fi
done

my_stop
