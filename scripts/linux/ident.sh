#!/bin/bash
#
# by Fabian Bieker <fabian.bieker@web.de>
# modified by DataSoft Corporation

. scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

SERVICE="ident"
HOST="serv"

STRINGSFILE=$5
USER=`perl -nle '/IDENT_USERNAME (.*)/ and print $1' < $STRINGSFILE`

my_start

read name

# remove control-characters
name=`echo $name | sed s/[[:cntrl:]]//g`

echo "$name" >> $LOG

name=`echo "$name" | sed -e 's/ //g'`
srcport=`echo "$name" | grep "[0-9][0-9]*,[0-9][0-9]*" `

if [ -z "$srcport" ]; then
	echo "$name : ERROR : INVALID-PORT "
	my_stop
fi

rand=$(($(od -An -N2 -i /dev/random)%3))

#rand=1
dstport=`echo "$srcport" | sed -e 's/.*,\([0-9][0-9]*\)/\1/'`
srcport=`echo "$srcport" | sed -e 's/\([0-9][0-9]*\),.*/\1/'`
#echo "$srcport,$dstport"

if [ $rand -eq 1 ]; then
	echo "$srcport,$dstport: 0 : LUNIX : root"
	my_stop	
fi

if [ $rand -eq 2 ]; then
	echo "$srcport,$dstport: 100 : LUNIX : $USER"
	my_stop
fi

echo "$srcport,$dstport: ERROR : NO-USER" 
my_stop
