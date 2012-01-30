#!/bin/bash
#
# $1: srcip, $2: srcport, $3: dstip, $4: dstport
#
# by Fabian Bieker <fabian.bieker@web.de>
#

. /usr/share/nova/scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

SERVICE="VNC"
HOST="bps-pc9"

my_start

echo -e "RFB 003.003\r"

while read name; do

	# remove control-characters
	name=`echo $name | sed s/[[:cntrl:]]//g`

	echo "$name" >> $LOG

	if [ `echo $name | grep "RFB 003.003" 2>&1 > /dev/null && echo 1` ]; then
		head -c 9 /dev/urandom
	else
		rand=`head -c 3 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -c 1`
		if [ $rand -le 4 ]; then
			my_stop
		fi
	fi
done

my_stop
