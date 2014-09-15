#!/bin/bash
#
# $1: srcip, $2: srcport, $3: dstip, $4: dstport, $5: config
#
# modified by Fabian Bieker <fabian.bieker@web.de>
# modified by DataSoft Corporation


. scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

STRINGSFILE=$5
VERSION=`perl -nle '/SSH_VERSION (.*)/ and print $1' < $STRINGSFILE`

SERVICE="ssh"
HOST="serv"


my_start

#------------------------------------------------------------------
# Objective for this script is to send the SSH/SSL version 
#  And to disconnect quickly.  
#
#  There currently isn't any SSL implemented in Honeyd, do go get a prompt we'd
# 	have to implement a basic SSL scheme here.
#------------------------------------------------------------------
echo -e "$VERSION\r\n"
#echo -e "SSH-1.0-OpenSSH_1.2\r\n"
sleep 1

#------------------------------------------------------------------
# For now comment this out to avoid corrupt packet message on clients
#------------------------------------------------------------------

#echo "Protocol mismatch."
#sleep 1
#
#while read name; do
#	echo "$name" >> $LOG
#	LINE=`echo "$name" | egrep -i "[\n ]"`
#	if [ -z "$LINE" ]; then
#		echo "Protocol mismatch."
#		my_stop	
#	else
#        echo "$name"
#	fi
#done

while read name; do
	echo "$name" >> $LOG
	LINE=`echo "$name" | egrep -i "[\n ]"`
	if [ -z "$LINE" ]; then
		echo "Protocol mismatch."
		my_stop	
	else
        echo "$name"
	fi
done
my_stop
