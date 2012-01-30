#!/bin/sh
#
# by Fabian Bieker <fabian.bieker@web.de>
#

. scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

SERVICE="LDAP"
HOST="bps-pc9"


my_start

read name

# remove control-characters
name=`echo $name | sed s/[[:cntrl:]]//g`

echo "$name" >> $LOG

my_stop
