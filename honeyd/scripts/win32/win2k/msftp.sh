#!/bin/bash
# 
# FTP (MSFTPD) Honeypot-Script intended for use with 
# Honeyd from Niels Provos 
# -> http://www.citi.umich.edu/u/provos/honeyd/
# 
# Author: Fabian Bieker <fabian.bieker@web.de>
# Based on: Maik Ellinger WU-FTPD Script
# Last modified: 08/03/2003
# Version: 0.0.1
# 
# Changelog:
# 0.0.1: initial release
# 

. /usr/share/honeyd//usr/share/nova/scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

SERVICE="MSFTP/FTP"
HOST="bps-pc9"

AUTH="no"
PASS="no"
DATFILES="/usr/share/nova/scripts/win32/win2k/dat/msftp.files"

pwd="/"
passive=0
#dataport=1234
dataport=$[$SRCPORT+1]
type="A"
mode="S"

my_start
echo -e "220 $HOST Microsoft FTP Service (Version 5.0).\r"

while read incmd parm1 parm2 parm3 parm4 parm5
do
	# remove control-characters
	incmd=`echo $incmd | sed s/[[:cntrl:]]//g`
	parm1=`echo $parm1 | sed s/[[:cntrl:]]//g`
	parm2=`echo $parm2 | sed s/[[:cntrl:]]//g`
	parm3=`echo $parm3 | sed s/[[:cntrl:]]//g`
	parm4=`echo $parm4 | sed s/[[:cntrl:]]//g`
	parm5=`echo $parm5 | sed s/[[:cntrl:]]//g`

	# convert to upper-case
	incmd_nocase=`echo $incmd | gawk '{print toupper($0);}'`
	#echo $incmd_nocase

	# log user input
	echo "$incmd $parm1 $parm2 $parm3 $parm4 $parm5" >> $LOG

	# check for login
	if [ "$AUTH" == "no" ]
        then
	    if [ "$incmd_nocase" != "USER" ]
            then 
		if [ "$incmd_nocase" != "QUIT" ]
    		then 
        	    echo -e "530 Please login with USER and PASS.\r"
		    continue
		fi
	    fi
	fi

	# parse cmds
	case $incmd_nocase in

	    QUIT* )	
			echo -e "221 \r"
            my_stop
		;;
	    SYST* )	
			echo -e "215 Windows_NT version 5.0"
        ;;
	    HELP* )
			echo -e "214-The following  commands are recognized(* ==>'s unimplemented).\r"
			echo -e "   ABOR\r\n   ACCT\r\n   ALLO\r\n   APPE\r\n   CDUP\r\n   CWD\r"
			echo -e "   DELE\r\n   HELP\r\n   LIST\r\n   MKD\r\n   MODE\r\n   NLST\r"
			echo -e "   NOOP\r\n   PASS\r\n   PASV\r\n   PORT\r\n   PWD\r\n   QUIT\r"
			echo -e "   REIN\r\n   REST\r\n   RETR\r\n   RMD\r\n   RNFR\r\n   RNTO\r"
			echo -e "   SITE\r\n   SMNT\r\n   STAT\r\n   STOR\r\n   STOU\r\n   STRU\r"
			echo -e "   SYST\r\n   TYPE\r\n   USER\r\n   XCUP\r\n   XCWD\r\n   XMKD\r"
			echo -e "   XPWD\r\n   XRMD\r"
			echo -e "214  HELP command successful.\r"
		;;
	    USER* )
			parm1_nocase=`echo $parm1 | gawk '{print toupper($0);}'`
			if [ "$parm1_nocase" == "ANONYMOUS" ]; then
		  		echo -e "331 Anonymous access allowed, send identity (e-mail name) as password.\r"
                AUTH="ANONYMOUS"
			else
			  echo -e "331 Password required for $parm1\r"
        	  AUTH=$parm1
			fi
		;;
	    PASS* )
            PASS=$parm1
			if [ "$AUTH" == "ANONYMOUS" ]; then
				rand=`head -c 4 /dev/urandom | hexdump | sed -e 's/[0 a-z]//g' | head -c 2`
			    echo -e "230 Anonymous user logged in.\r"
			else
			  echo -e "530 Login incorrect.\r"
			fi
		;;
	    MKD* )
			if [ `echo "$parm1" | grep ^/ >/dev/null && echo 1` ]; then

				if [ `cat $DATFILES | sed -e 's!/.*/$!/!' | grep "$parm1.*\[.*w.*\]" 2>&1 >/dev/null && echo 1` ]; then
					echo -e "257 \"$parm1\" new directory created.\r"
					echo -e "$parm1/\t[drwx]" | sed 's!//*!/!g' >> $DATFILES
				else
					echo -e "550 $parm1: Permission denied.\r"
				fi

			else

				if [ `grep "$pwd.*\[.*w.*\]" $DATFILES 2>&1 >/dev/null && echo 1` ]; then
					echo -e "257 \"$pwd/$parm1\" new directory created.\r"
					echo -e "$pwd/$parm1/\t[drwx]" | sed 's!//*!/!g' >> $DATFILES
				else
					echo -e "550 $parm1: Permission denied.\r"
				fi

			fi
		;;
		RMD* )
			if [ `echo "$parm1" | grep ^/ >/dev/null && echo 1` ]; then

				if [ `cat $DATFILES | sed -e 's!/.*/$!/!' | grep "$parm1.*\[.*w.*\]" 2>&1 >/dev/null && echo 1` ]; then
					echo -e "257 \"$parm1\" directory deleted.\r"
					#echo -e "$parm1/\t[drwx]" | sed 's!//*!/!g' >> $DATFILES
				else
					echo -e "550 $parm1: Permission denied.\r"
				fi

			else

				if [ `grep "$pwd.*\[.*w.*\]" $DATFILES 2>&1 >/dev/null && echo 1` ]; then
					echo -e "257 \"$pwd/$parm1\" directory deleted.\r"
					#echo -e "$pwd/$parm1/\t[drwx]" | sed 's!//*!/!g' >> $DATFILES
				else
					echo -e "550 $parm1: Permission denied.\r"
				fi

			fi

		;;
	    CWD* )
			oldpwd=$pwd
			if [ `echo $parm1 | grep ^/` ]; then
				pwd=`echo $parm1 | sed -e 's!//*!/!g' | sed -e 's!/[^/][^/]*/\.\.!!g'`
			else 
				pwd=`echo $pwd/$parm1 | sed -e 's!//*!/!g' | sed -e 's!/[^/][^/]*/\.\.!!g'`
			fi
			if [ `grep "$pwd" $DATFILES 2>&1 >/dev/null && echo 1` ]; then
				if [ `grep "$pwd.*\[.*[dx].*[dx].*\]" $DATFILES 2>&1 >/dev/null && echo 1` ]; then
					echo -e "250 CWD command successful.\r"
				else
					echo -e "550 $parm1: Permission denied.\r"
				fi
			else 
				echo -e "550 $parm1: Das System kann die angegebene Datei nicht finden.\r"
				pwd=$oldpwd
			fi
		;;
		PWD* )
			echo -e "257 \"$pwd\" is current directory.\r"
		;;
		LIST* )
			if [ `grep "$parm1" $DATFILES 2>&1 >/dev/null && echo 1` ]; then

				if [ `grep "$pwd/$parm1.*\[.*r.*\]" $DATFILES 2>&1 >/dev/null && echo 1` ]; then
					echo -e "150 Opening ASCII mode data connection for /bin/ls.\r"
					if [ $passive -eq 1 ]; then
						#echo -e "hallo\r" | nc -w 1 -l -p $dataport
						sleep 6
						echo -e "425 Can't build data connection: Connection Timeout\r"
					else
						#grep -E "`echo "^$pwd/$parm1/" | sed -e 's!//*!/!g'`[^/][^/]*/[^/]*$" $DATFILES | \
								#sed -e 's!/.*/\(.*\)/!\1!' | sed -e 's!//*!!g' | \
								#sed -e 's/\[\(.*\)d\(.*\)\]/\1\2/' | \
								#awk '{printf "drwx%s%s\t8\tftp\tftp\t4096\tFeb 28 22:11 %s\r\n", $2, $2, $1}' #| \
								#echo -e  "nc -w 1 -s 172.16.1.100 -p 20 172.16.1.5 $dataport\r"
								#echo -e  "hallo\r\n\r\n" | nc -w 1 -s 172.16.1.100 -p 20 172.16.1.5 $dataport 
								#nc -w 1-s $DSTIP -p 20 localhost $dataport 
						#echo -e "150 Opening ASCII mode data connection for file list.\r"
						#echo -e "226 Transfer complete.\r"
						#echo -e "226 Quotas off\r"
						
						echo -e "425 Can't build data connection: Connection refused\r"
					fi
				else 
					echo -e "550 $parm1: Permission denied.\r"
				fi
			
			else
			
				echo -e "550 $parm1: No such file or directory\r"
				
			fi
		;;
		RETR* )
			if [ `grep "$parm1" $DATFILES 2>&1 >/dev/null && echo 1` ]; then
					if [ $passive -eq 1 ]; then
						sleep 6
						echo -e "425 Can't build data connection: Connection Timeout\r"
					else 
						echo -e "425 Can't build data connection: Connection refused\r"
					fi
			else
				echo -e "550 $parm1: No such file or directory\r"
			fi
		;;
		STOR* )
				echo -e "550 $parm1: No such file or directory\r"
		;;
	    NOOP* )
			echo -e "200 NOOP command successful.\r"
		;;
	    PASV* )
			echo -e "227 Entering Passive Mode (192,168,1,2,165,53)\r"
			passive=1
			dataport=42293
		;;
		PORT* )
			#echo -e "500 Illegal PORT command.\r"
			echo -e "200 PORT command successfull.\r"
			#echo "parm1: $parm1"
			#dataport=$parm1
		;;
		ALLO* )
			if [ -z $parm1 ]; then
				echo -e "500 'ALLO': Invalid number of parameters\r"
			else
				echo -e "200 ALLO command successful.\r"
			fi
		;;
		TYPE*)
			echo -e "200 Type set to $parm1.\r"
			type=$parm1
		;;
		MODE*)
			echo -e "200 Mode set to $parm1.\r"
			mode=$parm1
		;;
		STAT* )
			echo -e "211-$HOST Microsoft Windows NT FTP Server status:\r"
		    echo -e "Version 5.0\r"
			echo -e "Connected to $HOST.$DOMAIN\r"
			echo -e "Logged in as $PASS\r"
			echo -e "TYPE: $type, FORM: Nonprint; STRUcture: File; transfer MODE: $mode\r"
			echo -e "No data connection\r"
		 	echo -e "211 End of status.\r"
		;;
	    ACCT* )
			echo -e "502 $incmd command not implemented.\r"
		;;
	    SMNT* )
			echo -e "502 $incmd command not implemented.\r"
		;;
	    REIN* )
			echo -e "502 $incmd command not implemented.\r"
		;;
	    MLFL* )
			echo -e "502 $incmd command not implemented.\r"
		;;
	    MAIL* )
			echo -e "502 $incmd command not implemented.\r"
		;;
	    MSND* )
			echo -e "502 $incmd command not implemented.\r"
		;;
	    MSON* )
			echo -e "502 $incmd command not implemented.\r"
		;;
	    MSAM* )
			echo -e "502 $incmd command not implemented.\r"
		;;
	    MRSQ* )
			echo -e "502 $incmd command not implemented.\r"
		;;
	    MRCP* )
			echo -e "502 $incmd command not implemented.\r"
		;;
	    MLFL* )
			echo -e "502 $incmd command not implemented.\r"
		;;
	    * )
			echo -e "500 '$incmd': command not understood.\r"
		;;
	esac
done

my_stop
