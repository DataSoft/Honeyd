#!/bin/bash
#
# by Fabian Bieker <fabian.bieker@web.de>
# modified by DataSoft Corporation

. scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

STRINGSFILE=$5
BANNER=`perl -nle '/TELNET_BANNER (.*)/ and print $1' < $STRINGSFILE`


SERVICE="telnet"
HOST="server"

state="login"
lastname=""
name=""
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
	echo -n "$HOST login: "

}

echo -e "$BANNER"
echo -n "$HOST login: "


while read name; do

	# remove non-ascii characters
	name=`echo "$name" | perl -pi -e 's/[[:^ascii:]]//g'`

	case $state in
	login)
		if [ -z "$name" ]; then
			login_failed
		else
			lastname="$name"
			state="pass"
			echo -n "Password: "
		fi
	;;
	pass)
		createNovaScriptAlert.py "$HONEYD_IP_SRC" "$HONEYD_INTERFACE" "telnet" "Attempted login with username / password of: $lastname / $name" || true
		login_failed
	;;
	esac
	
done
my_stop
