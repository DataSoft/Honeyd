#!/bin/bash
###############################################################################
##
##  Emulate a POP3 server
##
##  R MacGregor <rob.macgregor@techie.com> 24 October 2002 @ SANS
##
##  Version 0.0.2
##
####
##
##  CHANGELOG
##
##	24-10-2002: First pass written.
##	25-10-2002: First fully functional version.
##
####
##
## USAGE:
##
## emulate_pop3.sh IP SPORT
##
## IP: Attacker's IP address
## SPORT: Port being connected from
##
###############################################################################

# TRAP!
trap "echo 1 > /dev/null" SIGABRT SIGALRM SIGBUS SIGCHLD SIGCONT SIGFPE SIGHUP SIGILL SIGINT SIGIO SIGKILL SIGPIPE SIGPROF SIGPWR SIGQUIT SIGRTMAX SIGRTMAX-1 SIGRTMAX-10 SIGRTMAX-11 SIGRTMAX-12 SIGRTMAX-13 SIGRTMAX-14 SIGRTMAX-15 SIGRTMAX-2 SIGRTMAX-3 SIGRTMAX-4 SIGRTMAX-5 SIGRTMAX-6 SIGRTMAX-7 SIGRTMAX-8 SIGRTMAX-9 SIGRTMIN SIGRTMIN+1 SIGRTMIN+10 SIGRTMIN+11 SIGRTMIN+12 SIGRTMIN+13 SIGRTMIN+14 SIGRTMIN+15 SIGRTMIN+2 SIGRTMIN+3 SIGRTMIN+4 SIGRTMIN+5 SIGRTMIN+6 SIGRTMIN+7 SIGRTMIN+8 SIGRTMIN+9 SIGSEGV SIGSTOP SIGSYS SIGTERM SIGTRAP SIGTSTP SIGTTIN SIGTTOU SIGURG SIGUSR1 SIGUSR2 SIGVTALRM SIGWINCH SIGXCPU SIGXFSZ

ATTACKER_IP=${1:-127.0.0.1}
ATTACKER_SPORT=${2:-0}
ATTACKER_TSTAMP=`date +"%Y%m%d%H%M%S"`
DATE_STRING="+%Y-%m-%d %H:%M:%S"

BASE=`dirname ${0}`/POP.emulator
USER_FILE=${BASE}/pop.password
EMAIL_FILE=${BASE}/email

LOG=${BASE}/log/${ATTACKER_IP}:${ATTACKER_SPORT}_${ATTACKER_TSTAMP}.log

AUTH=""
COMMAND_LINE=""
SECOND=""

log()
	{
	MESSAGE="${*}"
	echo "`date -u "${DATE_STRING}"` RESP: ${MESSAGE}" >> ${LOG}
	}

message()
	{
	MESSAGE="${*}"

	echo "${MESSAGE}"
	log ${MESSAGE}
	}

do_quit()
	{
	if [ -n "${ONCE_A_MESSAGE}" -a -z "${MAIL_MESSAGES}" ]; then
		message "-ERR some deleted messages not removed"
	    else
		message "+OK Have a nice day"
	fi

	exit
	}

# Tell them who we are
echo "+OK POP3 `hostname` V1999 server ready"

echo "Connection from ${ATTACKER_IP} to ${ATTACKER_SPORT} started at `date -u`" > ${LOG}

while true; do
	{
	read -r COMMAND_LINE SECOND DUMMY
	log "`date -u "${DATE_STRING}"` CMD: >${COMMAND_LINE} ${SECOND} ${DUMMY}<" >> ${LOG}

	COMMAND_LINE=`echo "${COMMAND_LINE}" | tr [:lower:] [:upper:] | tr -d [:cntrl:]`
	SECOND=`echo "${SECOND}" | tr -d [:cntrl:]`
	DUMMY=`echo "${DUMMY}" | tr -d [:cntrl:]`

	if [ -z "${AUTH}" ]; then
		case "${COMMAND_LINE}" in
			USER )	# Ok, must get the USER command first
				if [ -z "${SECOND}" ]; then
					message "-ERR Missing username argument"
					unset AUTH USER
				    else
					grep -q "^${SECOND}:" ${USER_FILE}
					STATUS=${?}
					if [ ${?} -eq 0 ]; then
						message "+OK Hello ${SECOND}, password please"
						AUTH=U
						USER="${SECOND}"
					    else
						message "-ERR Unknown AUTHORIZATION state command"
						unset AUTH USER
					fi
				fi
				;;
			QUIT )	do_quit
				;;
			"" ) message "-ERR Null command"
				unset AUTH USER
				;;
			* )	message "-ERR Unknown AUTHORIZATION state command"
				unset AUTH USER
				;;
			esac	
	    else
		if [ "${AUTH}" = "U" ]; then
			case "${COMMAND_LINE}" in
				PASS )	# Ok, must get password next
					PASS=`grep "^${USER}:" ${USER_FILE} | cut -d: -f2-`
					if [ "${PASS}" = "${SECOND}" ]; then
						if [ ! -f "${EMAIL_FILE}.${USER}" ]; then
							message "+OK Mailbox open, 0 messages"
						    else
							message "+OK Mailbox open, 1 message"
							MAIL_MESSAGES=y
							ONCE_A_MESSAGE=y
						fi
						AUTH=Y
					   else
						message "-ERR Bad login"
						unset AUTH USER PASS
					fi
					;;
				QUIT )	do_quit
					;;
				"" ) message "-ERR Null command"
					;;
				* )	message "-ERR Unknown AUTHORIZATION state command"
					unset AUTH USER PASS
					;;
				esac
		    else
			
			case "${COMMAND_LINE}" in
				QUIT )	do_quit
					;;
				STAT ) if [ -z "${MAIL_MESSAGES}" ]; then
						message "+OK 0 0"
					    else
						message "+OK 1 `cat ${EMAIL_FILE}.${USER}|wc -c|sed 's/[ ]*//'`"
					fi
					;;
				NOOP ) message "+OK Twiddling my thumbs"
					;;
				REST ) message "+OK"
					if [ -n "${ONCE_A_MESSAGE}" ]; then
						MAIL_MESSAGES=y
					fi
					;;
				LIST ) if [ -n "${MAIL_MESSAGES}" -a "${SECOND}" = "1" ]; then
						message "+OK 1 message (`cat ${EMAIL_FILE}.${USER}|wc -c|sed 's/[ ]*//'` octets)"
						message "+OK 1 `cat ${EMAIL_FILE}.${USER}|wc -c|sed 's/[ ]*//'`"
					    else
						message "-ERR no such message"
					fi
					;;
				RETR ) if [ -n "${MAIL_MESSAGES}" -a "${SECOND}" = "1" ]; then
						message "+OK `cat ${EMAIL_FILE}.${USER}|wc -c|sed 's/[ ]*//'` octets"
						log "Displayed file ${EMAIL_FILE}.${USER}"
						cat ${EMAIL_FILE}.${USER}
					    else
						message "-ERR no such message"
					fi
					;;
				DELE ) if [ -n "${MAIL_MESSAGES}" -a "${SECOND}" = "1" ]; then
						message "+OK message ${SECOND} deleted"
						unset MAIL_MESSAGES
					    else
						message "-ERR no such message"
					fi
					;;
				"" ) message "-ERR Null command"
					;;

				* ) message "-ERR Unknown TRANSACTION state command"
					;;
			esac
		fi
	fi

	}
done
