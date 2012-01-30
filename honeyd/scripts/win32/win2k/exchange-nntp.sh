#!/bin/bash
#
# by Fabian Bieker <fabian.bieker@web.de>
#

. scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

SERVICE="exchange/NNTP"
HOST="bps-pc9"

post=""
user=""
auth="no"

my_start
echo -e "200 NNTP-Dienst 5.00.0984 Version: 5.0.2195.5329 Posting Allowed\r"

while read incmd parm1 parm2 parm3 parm4 parm5; do

	# remove control-characters
	incmd=`echo $incmd | sed s/[[:cntrl:]]//g`
	parm1=`echo $parm1 | sed s/[[:cntrl:]]//g`
	parm2=`echo $parm2 | sed s/[[:cntrl:]]//g`
	parm3=`echo $parm3 | sed s/[[:cntrl:]]//g`
	parm4=`echo $parm4 | sed s/[[:cntrl:]]//g`
	parm5=`echo $parm5 | sed s/[[:cntrl:]]//g`

	incmd_nocase=`echo $incmd | gawk '{print toupper($0);}'`

	#echo "$incmd $parm1 $parm2 $parm3 $parm4 $parm5" >> $LOG

	case $incmd_nocase in
	QUIT)
		echo -e "205 closing connection - goodbye!\r"
		my_stop
	;;
	AUTHINFO)
		if [ -n $parm1 ]; then
			incmd_nocase=`echo $incmd | gawk '{print toupper($0);}'`

			case $parm1_nocase in
			USER)
				if [ -n $parm2 ]; then
					user=$parm2
					echo -e "381 Waiting for password\r"
				else
					echo -e "501 Syntax Error in Command\r"
				fi
			;;
			PASS)
				if [ -n $parm2 ]; then
					if [ -n $user ]; then
						rand=`head -c 3 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -c 1`
						if [ $rand -le 3 ]; then	
							auth="ok"
							echo -e "281 Authentication ok\r"
						else 
							auth=""
							user=""
							echo -e "502 Permission denied\r"
						fi
					else
						echo -e "503 Give username first\r"
					fi
				else
					echo -e "501 Syntax Error in Command\r"
				fi

			;;
			GENERIC|TRANSACT)
				echo -e "281 Packages Follow\r"
				echo -e "NTLM\r\n.\r"
			;;
			*)
				echo -e "501 Syntax Error in Command\r"
			;;
			esac
			
		else
			echo -e "501 Syntax Error in Command\r"
		fi
	;;
	HELP)
		echo -e "100 Legal commands are :\r"
		echo -e "article [MessageID|Number]\r"
		echo -e "authinfo [user|pass|generic|transact] <data>\r"
		echo -e "body [MessageID|Number]\r"
		echo -e "check <message-id>\r"
		echo -e "date\r\ngroup newsgroup\r\nhead [MessageID|Number]\r\nhelp\r\nihave <message-id>\r"
		echo -e "last\r\nlist [active|newsgroups[wildmat]|srchfields|searchable|prettynames[wildmat]]\r"
		echo -e "listgroup [newsgroup]\r\nmode stream|reader\r\nnewgroups yymmdd hhmmss ["GMT"] [<distributions>]\r"
		echo -e "newnews wildmat yymmdd hhmmss ["GMT"] [<distributions>]\r\nnext\r\npost\r\nquit\r\nsearch\r"
		echo -e "stat [MessageID|number]\r\nxhdr header [range|MessageID]\r\nxover [range]\r"
		echo -e "xpat header range|MessageID pat [morepat ...]\r"
		echo -e "xreplic newsgroup/message-number[,newsgroup/message-number...]\r\ntakethis <message-id>\r"
		echo -e ".\r"
	;;
	LIST)
		echo -e "215 list of newsgroups follow\r"
		echo -e "control.cancel 0 1 y\r"
		echo -e "control.newgroup 0 1 y\r"
		echo -e "control.rmgroup 0 1 y\r"
		echo -e ".\r"
	;;
	LISTGROUP)
		echo -e "listgroup $parm1\r"
		echo -e "211\r"
		echo -e ".\r"
		#echo -e "411 no such newsgroup"
	;;
	GROUP)
		if [ -n $parm1 ]; then
			echo -e "211 0 1 0 $parm1\r"
		else
			echo -e "501 Syntax Error in Command\r"
		fi
	;;
	ARTICLE|HEAD|BODY|STAT|XHDR)
		if [ -n $parm1 ]; then
			echo -e "423 no such article number in group\r"
		else 
			echo -e "420 no current article has been selected\r"
		fi
	;;
	NEXT|LAST|XOVER)
		echo -e "420 no current article has been selected\r"
	;;
	CHECK|IHAVE)
		echo -e "502 Access Denied.\r"
	;;
	POST)
		echo -e "340 Continue posting - terminate with period"
		post="post"
	;;
	TAKETHIS)
		post="takethis"
	;;
	SEARCH)
		if [ -n $parm1 ]; then
			echo -e "224 Overview information follows\r\n.\r"
		else
			echo -e "501 Syntax Error in Command\r"
		fi
	;;
	XPAT|XREPLIC)
		echo -e "501 Syntax Error in Command\r"
	;;
	MODE)
		if [ $parm1 == "reader" -o $parm1 == "READER" ]; then
			echo -e "200 NNTP-Dienst 5.00.0984 Version: 5.0.2195.5329 Posting Allowed\r"
		else
			echo -e "500 Command Not Recognized"
		fi
	;;
	DATE)
		echo "111 `date +%Y%m%d%H%M%S`"
	;;
	*)
		if [ -z $post ]; then
			echo -e "500 Command Not Recognized\r"
		else
			if [ $incmd_nocase == "." ]; then
				if [ $post == "post" ]; then
					echo -e "441 (605) Article Rejected -- Bad Article"
				fi
				if [ $post == "takethis" ]; then
					echo -e "439 NULL (605) Transfer Failed - Do Not Try Again -- Bad Article"
				fi
				post=""
			fi
		fi
	;;
	esac
done

my_stop
