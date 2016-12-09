#!/bin/bash
# 
# FTP (WU-FTPD) Honeypot-Script intended for use with 
# Honeyd from Niels Provos 
# -> http://www.citi.umich.edu/u/provos/honeyd/
# 
# Author: Maik Ellinger
# modified by DataSoft Corporation
# 
# Changelog:
# 0.0.8; some ftp comamnds implemented: PWD, TYPE, MODE, PORT (by Fabian Bieker)
#
# 0.0.7; psyeudo filesystem added (by Fabian Bieker)
#
# 0.0.6; some ftp comamnds implemented (MKD)
# 
# 0.0.4; some ftp comamnds implemented (CWD)
# 
# 0.0.3: some bugfixes/new commands implemented
#
# 0.0.1: initial release
# 

. scripts/misc/base.sh

SRCIP=$1
SRCPORT=$2
DSTIP=$3
DSTPORT=$4

STRINGSFILE=$5
VERSION=`perl -nle '/FTPD_VERSION (.*)/ and print $1' < $STRINGSFILE`

SERVICE="wu-ftpd/FTP"
HOST="serv"

AUTH="no"
PASS="no"
DATFILES="scripts/suse7.0/dat/wuftpd.files"

pwd="/"
passive=0
#dataport=1234
dataport=$[$SRCPORT+1]
type="A"
mode="S"

my_start

echo -e "220 $HOST.$DOMAIN $VERSION $DATE) ready.\r"
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
	incmd_nocase=`echo $incmd | awk '{print toupper($0);}'`
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
			echo -e "221 Goodbye.\r"
            my_stop
		;;
	    SYST* )	
			echo -e "215 UNIX Type: L8\r"
        ;;
	    HELP* )
			echo -e "214-The following commands are recognized (* =>'s unimplemented).\r"
			echo -e "   USER    PORT    STOR    MSAM*   RNTO    NLST    MKD     CDUP\r"
			echo -e "   PASS    PASV    APPE    MRSQ*   ABOR    SITE    XMKD    XCUP\r"
			echo -e "   ACCT*   TYPE    MLFL*   MRCP*   DELE    SYST    RMD     STOU\r"
			echo -e "   SMNT*   STRU    MAIL*   ALLO    CWD     STAT    XRMD    SIZE\r"
			echo -e "   REIN*   MODE    MSND*   REST    XCWD    HELP    PWD     MDTM\r"
			echo -e "   QUIT    RETR    MSOM*   RNFR    LIST    NOOP    XPWD\r"
			echo -e "214 Direct comments to ftp@$domain.\r"
		;;
	    USER* )
			parm1_nocase=`echo $parm1 | awk '{print toupper($0);}'`
			createNovaScriptAlert.py "$HONEYD_IP_SRC" "$HONEYD_INTERFACE" "Linux FTP" "Attempted login with username of $parm1" || true
			if [ "$parm1_nocase" == "ANONYMOUS" ]; then
		  		echo -e "331 Guest login ok, send your complete e-mail address as a password.\r"
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
			    echo -e "230-Hello User at $SRCIP,\r"
			    echo -e "230-we have $rand users (max 100) logged in in your class at the moment.\r"
			    echo -e "230-Local time is: $DATE\r"
			    echo -e "230-All transfers are logged. If you don't like this, disconnect now.\r"
			    echo -e "230-\r"
		    	echo -e "230-tar-on-the-fly and gzip-on-the-fly are implemented; to get a whole\r"
			    echo -e "230-directory \"foo\", \"get foo.tar\" or \"get foo.tar.gz\" may be used.\r"
			    echo -e "230-Please use gzip-on-the-fly only if you need it; most files already\r"
			    echo -e "230-are compressed, and I will kill your processes if you waste my\r"
		    	echo -e "230-ressources.\r"
			    echo -e "230-\r"
			    echo -e "230-The command \"site exec locate pattern\" will create a list of all\r"
			    echo -e "230-path names containing \"pattern\".\r"
		    	echo -e "230-\r"
			    echo -e "230 Guest login ok, access restrictions apply.\r"
			else
			  echo -e "530 Login incorrect.\r"
			fi
		;;
	    MKD* )
			if [ `echo "$parm1" | grep ^/ 2>&1 >/dev/null && echo 1` ]; then

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
				echo -e "550 $parm1: No such file or directory\r"
				pwd=$oldpwd
			fi
		;;
		PWD* )
			echo -e "257 \"$pwd\" is current directory.\r"
		;;
		LIST* )
			if [ `grep "$parm1" $DATFILES 2>&1 >/dev/null && echo 1` ]; then

				if [ `grep "$pwd/$parm1.*\[.*r.*\]" $DATFILES 2>&1 >/dev/null && echo 1` ]; then
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
			echo -e "200 PORT command successful.\r"
			#echo "parm1: $parm1"
			#dataport=$parm1
		;;
		ALLO* )
			echo -e "202 No storage allocation necessary.\r"
		;;
		TYPE*)
			echo -e "200 Type set to $parm1.\r"
			type=$parm1
		;;
		MODE*)
			echo -e "200 Mode set to $parm1.\r"
			mode=$parm1
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
