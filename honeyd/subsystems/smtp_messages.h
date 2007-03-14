/*
 * Copyright (c) 2005 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#ifndef _SMTP_MESSAGES_H_
#define _SMTP_MESSAGES_H_

static struct keyvalue help[] = {
	{"sendmail", "214-2.0.0 This is sendmail version 8.12.9\n214-2.0.0 Topics:\n214-2.0.0       HELO    EHLO    MAIL    RCPT    DATA\n214-2.0.0       RSET    NOOP    QUIT    HELP    VRFY\n214-2.0.0       EXPN    VERB    ETRN    DSN     AUTH\n214-2.0.0 For more info use \"HELP <topic>\".\n214-2.0.0 To report bugs in the implementation send email to\n214-2.0.0       sendmail-bugs@sendmail.org.\n214-2.0.0 For local information send email to Postmaster at your site.\n214 2.0.0 End of HELP info\n" },
	{ "postfix", "502 Error: command not implemented\n" },
	{ NULL, NULL }
};

struct keyvalue helperror[] = {
	{ "sendmail", "504 5.3.0 HELP topic \"$helpask\" unknown\n" },
	{ "postfix",  "502 Error: command not implemented\n" },
	{ NULL, NULL }
};


struct keyvalue welcome[] = {
	{ "sendmail", "220 $hostname ESMTP Sendmail 8.12.9/8.11.3; $datum\n" },
	{ "postfix", "220 $hostname ESMTP Postfix\n" },
	{ NULL, NULL }
};

struct keyvalue helo[] = {
	{ "sendmail",
	  "250-$hostname. Hello $srcname [$srcipaddress], "
	  "pleased to meet you\n" },
	{ "postfix", "250-$hostname\n" },
	{ NULL, NULL }
};

struct keyvalue heloerror[] = {
	{ "sendmail", "501 5.0.0 helo requires domain address\n" },
	{ "postfix" , "501 Syntax: HELO hostname\n" },
	{ NULL, NULL }
};

struct keyvalue ehlo[] = {
	{ "sendmail", "250-$hostname Hello $srcname [$srcipaddress], pleased to meet you\n250-ENHANCEDSTATUSCODES\n250-PIPELINING\n250-EXPN\n250-VERB\n250-8BITMIME\n250-SIZE 5000000\n250-DSN\n250-ETRN\n250-DELIVERBY\n250 HELP\n" },
	{ "postfix",  "250-$hostname.\n250-PIPELINING\n250-SIZE 10240000\n250-ETRN\n250 8BITMIME\n" },
	{ NULL, NULL },
};

struct keyvalue ehloerror[] = {
	{ "sendmail", "501 5.0.0 ehlo requires domain address\n" },
	{ "postfix" , "501 Syntax: EHLO hostname\n" },
	{ NULL, NULL }
};

struct keyvalue mailfrom[] = {
	{ "sendmail", "250 2.1.0 $sender... Sender ok\n" },
	{ "postfix", "250 Ok\n" },
	{ NULL, NULL }
};

struct keyvalue mailfromerror[] = {
	{ "sendmail", "503 5.5.0 Sender already specified\n" },
	{ "postfix", "503 Error: nested MAIL command\n" },
	{ NULL, NULL }
};

struct keyvalue errors[] = {
	{ "sendmail", "500 5.5.1 Command unrecognized: \"$cmd\"\n" },
	{ "postfix", "502 Error: command not implemented\n" },
	{ NULL, NULL }
};

struct keyvalue rcptto[] = {
	{ "sendmail", "250 2.1.5 $recipient... Recipient ok\n" },
	{ "postfix", "250 Ok\n" },
	{ NULL, NULL }
};

struct keyvalue rcpttoerror[] = {
	{ "sendmail", "503 5.0.0 Need MAIL before RCPT\n" },
	{ "postfix", "503 Error: need MAIL command\n" },
	{ NULL, NULL }
};

struct keyvalue data[] = {
	{ "sendmail", 
	  "354 Enter mail, end with \".\" on a line by itself\n" },
	{ "postfix", "354 End data with <CR><LF>.<CR><LF>\n" },
	{ NULL, NULL }
};

struct keyvalue datanomail[] = {
	{ "sendmail", "503 5.0.0 Need MAIL command\n" },
	{ "postfix",  "503 Error: need MAIL command\n" },
	{ NULL, NULL }
};

struct keyvalue datanorcpt[] = {
	{ "sendmail", "503 5.0.0 Need RCPT (recipient)\n" },
	{ "postfix", "554 Error: no valid recipients\n" },
	{ NULL, NULL }
};

struct keyvalue quit[] = {
	{ "sendmail", "221 $hostname closing connection\n" },
	{ "postfix", "221 Bye\n" },
	{ NULL, NULL }
};

struct keyvalue dot[] = {
	{ "sendmail", "250 2.0.0 $queuenr Message accepted for delivery\n" },
	{ "postfix", "250 Ok: queued as $queuenr\n" },
	{ NULL, NULL }
};

struct keyvalue vrfy[] = {
	{ "sendmail", "250 2.1.5 <$realuser>\n" },
	{ "postfix", "252 <$realuser>\n" },
	{ NULL, NULL }
};

struct keyvalue vrfyerror[] = {
	{ "sendmail", "501 5.5.2 Argument required\n" },
	{ "postfix", "501 Syntax: VRFY address\n" },
	{ NULL, NULL }
};

struct keyvalue vrfynouser[] = {
	{ "sendmail", "550 5.1.1 $vrfyuser... User unknown\n" },
	{ "postfix", "252 <$vrfyuser>\n" },
	{ NULL, NULL }
};

struct keyvalue rset[] = {
	{ "sendmail", "250 2.0.0 Reset state\n" },
	{ "postfix", "250 Ok\n" },
	{ NULL, NULL }
};

struct keyvalue noop[] = {
	{ "sendmail", "250 2.0.0 OK\n" },
	{ "postfix", "250 Ok\n" },
	{ NULL, NULL }
};

#endif /* _SMTP_MESSAGES_H_ */
