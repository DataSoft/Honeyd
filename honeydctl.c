/*
 * Copyright (c) 2000, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * Copyright (c) 1997 Brian Somers <brian@Awfulhak.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>

#include "config.h"

#include <sys/time.h>
#include <err.h>
#include <errno.h>
#ifdef HAVE_LIBEDIT
#include <histedit.h>
#endif
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>

#ifdef HAVE_LIBREADLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#if !defined(HAVE_LIBEDIT) && !defined(HAVE_LIBREADLINE)
#error "Need either libedit or libreadline"
#endif

#define LINELEN 2048
char Buffer[LINELEN];

#define CTLNAME		"honeydctl"
#define HONEYD_SOCK	"/var/run/honeyd.sock"

int
usage()
{
    fprintf(stderr,
	"usage: %s [-v] [-t n] [LocalSock]\n"
	"\t -v tells %s to output all conversation\n"
	"\t -t n specifies a timeout of n seconds when connecting\n",
	CTLNAME, CTLNAME);
    exit(1);
}

int TimedOut = 0;

void
Timeout(int Sig)
{
    TimedOut = 1;
}

#define REC_SHOW    (2)
#define REC_VERBOSE (4)

char *passwd;
char *prompt;

#ifdef HAVE_LIBEDIT
char *
getprompt(EditLine *e)
{
	if (prompt == NULL)
		prompt = "";
	return prompt;
}
#endif

int
receive(int fd, int display)
{
    int Result;
    int len;
    char *last;

    prompt = Buffer;
    len = 0;
    while (Result = read(fd, Buffer+len, sizeof(Buffer)-len-1), Result != -1) {
        if (Result == 0 && errno != EINTR) {
          Result = -1;
          break;
        }
        len += Result;
        Buffer[len] = '\0';
        if (len > 2 && !strcmp(Buffer+len-2, "> ")) {
            prompt = strrchr(Buffer, '\n');
            if (display & (REC_SHOW|REC_VERBOSE)) {
                if (display & REC_VERBOSE)
                    last = Buffer+len-1;
                else
                    last = prompt;
                if (last) {
                    last++;
                    if(write(1, Buffer, last-Buffer) == -1)
			{
                  syslog(LOG_ERR, "Failed to write to file descriptor");
                  exit(EXIT_FAILURE);
				//errx(EXIT_FAILURE, "Failed to write to file descriptor");
			}
                }
            }
            prompt = prompt == NULL ? Buffer : prompt+1;
            for (last = Buffer+len-2; last > Buffer && *last != ' '; last--)
                ;
            if (last > Buffer+3 && !strncmp(last-3, " on", 3)) {
                 /* a password is required ! */
                Result = 1;
            } else
                Result = 0;
            break;
        }
        if (len == sizeof (Buffer) - 1) {
            int flush;
            if ((last = strrchr(Buffer, '\n')) == NULL)
                /* Yeuch - this is one mother of a line ! */
                flush = sizeof (Buffer) / 2;
            else
                flush = last - Buffer + 1;
            if(write(1, Buffer, flush) == -1)
		{
            syslog(LOG_ERR, "Failed to write to file descriptor");
            exit(EXIT_FAILURE);
			//errx(EXIT_FAILURE, "Failed to write to file descriptor");
		}
            strlcpy(Buffer, Buffer + flush, sizeof(Buffer));
            len -= flush;
        }
    }

    return Result;
}

int data = -1;
jmp_buf pppdead;

void
check_fd(int sig)
{
	if (data != -1) {
		struct timeval t;
		fd_set f;
		static char buf[LINELEN];
		int len;

		FD_ZERO(&f);
		FD_SET(data, &f);
		t.tv_sec = t.tv_usec = 0;
		if (select(data+1, &f, NULL, NULL, &t) > 0) {
			len = read(data, buf, sizeof (buf));
			if (len > 0)
			{
				if(write(fileno(stdout), buf, len))
				{
					syslog(LOG_ERR, "Failed to write to file descriptor");
					exit(EXIT_FAILURE);
					//errx(EXIT_FAILURE, "Failed to write to file descriptor");
				}
			}
			else
				longjmp(pppdead, -1);
		}
	}
}

const char *
#ifdef HAVE_LIBEDIT
smartgets(EditLine *e, int *count, int fd)
#else
smartgets(int *count, int fd)
#endif
{
  const char *result;

  data = fd;
  signal(SIGALRM, check_fd);
  ualarm(500000, 500000);
  result = setjmp(pppdead) ? NULL :
#ifdef HAVE_LIBEDIT
      el_gets(e, count);
#else
      readline(prompt);
  if (result != NULL)
	  *count = strlen(result);
#endif      
  ualarm(0,0);
  signal(SIGALRM, SIG_DFL);
  data = -1;

  return result;
}

int
main(int argc, char **argv)
{
	struct sockaddr *sock;
	struct sockaddr_un ifsun;
	int fd, len, display, save_errno;
	unsigned TimeoutVal;
	struct sigaction act, oact;
	char *sockname = HONEYD_SOCK;
#ifdef HAVE_LIBEDIT
	EditLine *edit;
	History *hist;
	HistEvent hev = { 0, "" };
#endif
	const char *l;
	int ch;

	display = REC_SHOW;
	TimeoutVal = 2;

	while ((ch = getopt(argc, argv, "t:v")) != -1) {
		switch (ch) {
		case 't':
			TimeoutVal = (unsigned)atoi(optarg);
			break;
    
		case 'v':
			display += REC_VERBOSE;
			break;
		default:
			usage();
		}
	}

        argc -= optind;
        argv += optind;

	if (argc > 0)
		sockname = argv[0];

	sock = (struct sockaddr *)&ifsun;
	
	memset(&ifsun, '\0', sizeof (ifsun));
#ifdef HAVE_SUN_LEN
	ifsun.sun_len = strlen(sockname);
	if (ifsun.sun_len > sizeof (ifsun.sun_path) - 1)
		errx(1, "%s: path too long", sockname);
#endif /* HAVE_SUN_LEN */

	ifsun.sun_family = AF_UNIX;
	strlcpy(ifsun.sun_path, sockname, sizeof(ifsun.sun_path));

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
		syslog(LOG_ERR, "Cannot create local domain socket");
		exit(EXIT_FAILURE);
	}
		//errx(2, "cannot create local domain socket");

	TimedOut = 0;
	if (TimeoutVal) {
		act.sa_handler = Timeout;
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0;
		sigaction(SIGALRM, &act, &oact);
		alarm(TimeoutVal);
	}

	if (connect(fd, sock, sizeof (ifsun)) == -1) {
		if (TimeoutVal) {
			save_errno = errno;
			alarm(0);
			sigaction(SIGALRM, &oact, 0);
			errno = save_errno;
		}
		if (TimedOut)
			warnx("timeout: cannot connect to socket %s",
			    sockname);
		else
			warn("cannot connect to socket %s", sockname);
		close(fd);
		return 3;
	}

	if (TimeoutVal) {
		alarm(0);
		sigaction(SIGALRM, &oact, 0);
	}

	/* Get Prompt ? */
	receive(fd, display);

#ifdef HAVE_LIBEDIT
	hist = history_init();
#  ifdef H_SETSIZE
	history(hist, &hev, H_SETSIZE, 20);
	edit = el_init("honeydctl", stdin, stdout, stderr);
#  else /* !H_SETSIZE */
	history(hist, H_EVENT, 20);
	edit = el_init("honeydctl", stdin, stdout);
#  endif

	el_source(edit, NULL);
	el_set(edit, EL_PROMPT, getprompt);
	el_set(edit, EL_EDITOR, "emacs");
	el_set(edit, EL_SIGNAL, 1);
	el_set(edit, EL_HIST, history, (const char *)hist);
#endif
	
#ifdef HAVE_LIBEDIT
	while ((l = smartgets(edit, &len, fd))) {
		if (len > 1)
#	ifdef H_SETSIZE
			history(hist, &hev, H_ENTER, l);
#	else
			history(hist, H_ENTER, l);
#	endif /* H_SETSIZE */
#else /* !HAVE_LIBEDIT */
	while ((l = smartgets(&len, fd))) {
		char line[128];
		if (len > 0) {
			add_history((char *)l);
			snprintf(line, sizeof(line), "%s\n", l);
			l = line;
			len++;
		}
#endif
		if(write(fd, l, len) == -1){
			syslog(LOG_ERR, "Failed to write to file descriptor");
			exit(EXIT_FAILURE);
		}
		if (receive(fd, display) != 0)
			break;
	}
	fprintf(stderr, "Connection closed\n");
#ifdef HAVE_LIBEDIT
	el_end(edit);
	history_end(hist);
#endif
	close(fd);
    
	return 0;
}
