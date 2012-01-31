#!/bin/sh
#
# provide some functions and vars for honeyd scripts
#
# Copyright (C) 2003  Fabian Bieker <fabian.bieker@web.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

LOG="/var/log/honeyd/scriptLog.log"
DATE=`date`
SERVICE="undef"
HOST="undef"
DOMAIN="local.mynet"

my_start() {
	echo "--MARK--,\"$DATE\",\"$SERVICE\",\"$SRCIP\",\"$DSTIP\",$SRCPORT,$DSTPORT," >> $LOG
	echo -n "\"" >> $LOG
}

my_stop() {
	echo "\"," >> $LOG
	echo "--ENDMARK--" >> $LOG
	exit 0
}
