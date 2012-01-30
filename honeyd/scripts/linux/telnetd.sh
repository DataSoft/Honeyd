#!/bin/bash
#
# by Fabian Bieker <fabian.bieker@web.de>
# modified by DataSoft Corporation

. /usr/share/nova/scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

STRINGSFILE=$5
BANNER=`perl -nle '/TELNET_BANNER (.*)/ and print $1' < $STRINGSFILE`


SERVICE="telnet"
HOST="serv"

state="login"
count=1

my_start

login_failed() {
	sleep 3
	echo "Login incorrect"
	if [ $count -eq 4 ]; then
		my_stop
	fi
	count=$[$count+1]
	state="login"

	echo ""
	echo -n "$HOST Login: "

}

echo -e $BANNER
echo -n "$HOST Login: "


while read name; do

	# remove control-characters
	name=`echo $name | sed s/[[:cntrl:]]//g`

	echo "$name" >> $LOG


	case $state in
	login)
		if [ -z $name ]; then
			login_failed
		else
			state="pass"
			echo -n "Password: "
		fi
	;;
	pass)
		login_failed
	;;
	esac
	
done
my_stop
