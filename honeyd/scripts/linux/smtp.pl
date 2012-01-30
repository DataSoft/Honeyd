#!/usr/bin/perl
#
# Spam Bait and Analyzer for Honeyd
#
# Copyright 2003 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
# For the license refer to the main source code of Honeyd.

=head1 NAME

smtp.pl - a configurable SPAM trap and detector

=head1 SYNOPSIS

smtp.pl [-qr] [-h hostname] [-n emailaddr] [mailstore]

=head1 DESCRIPTION

Start smtp.pl as a Honeyd service.  You may use the directory in which
smtp.pl stores its files are first argument to the script.  Make sure
that you have all necessary dependencies.  You can use the script as
command line tool for testing.

Currently, it knows how to simulate the behavior of "F<sendmail>" and
"F<postfix>".

The options are as follows:

=over 6

=item -q

This option specifies that the first few email from a spammer
should be queued for delivery.  A separate process is needed
to send queued email.

=item -r

Report captured email to Razor for spam classification.
The Razor2 module is required.

=item -h

This option sets the hostname that the spam trap is using.
The name is seens on the first output line when contacting
the spam trap.

=item -n

This option allows the spam trap to report captured
messages via email.  The mailstore is the directory in which
this program stores all received messages.

=back

=head1 AUTHOR

This spam bait utility was developed by Niels Provos.

=cut

use warnings;
use POSIX qw(strftime);
use Fcntl ':flock'; # import LOCK_* constants

######
#
# Static Configuration
#
######
$mailstore = "/tmp/mailstore";
$hostname = "";
$alarmtime = 30;
$reportemail = "";
$queuemode = 0;
$razormode = 0;
$razorhome = "";

#
# End of Configuration
#
##############

# Argument Overrides
while ($ARGV[0] && substr($ARGV[0], 0, 1) eq "-") {
    $option = shift @ARGV;
 SWITCH: {
	if ($option =~ /^-r$/) {
	    $razorhome = shift @ARGV;
	    die "Can not find Razor's config file" unless -f $razorhome;
	    $razormode = 1;
	    last SWITCH;
	} elsif ($option =~ /^-q$/) {
	    $queuemode = 1;
	    last SWITCH;
	} elsif ($option =~ /^-n$/) {
	    $reportemail = shift @ARGV;
	    last SWITCH;
	} elsif ($option =~ /^-h$/) {
	    $hostname = shift @ARGV;
	    last SWITCH;
	} else {
	    print STDERR "Unknown options $option\n";
	    exit;
	}
    }
}

$mailstore = $ARGV[0] if $ARGV[0];

# Generate some random host names

@domains = (
"iridic", "bocoy", "hers", "alfa", "chital", "sound", "razz",
"update", "gown", "teeter", "embark", "valeta", "sipid", "whally",
"dewcup", "shabby", "eral", "kibble", "samh", "artha", "zither",
"bench", "duffel", "census", "hacker", "booger", "hobbil", "apish",
"arris", "thyme", "stays", "begut", "unhid", "subgod", "genal",
"fluty", "gossy", "skiver", "secque", "fetish", "osse", "dipyre",
"germin", "datary", "muffle", "refuse", "semis", "vireo", "riser",
"panada", "rackle", "dhyana", "crena", "upcall", "cumbu", "pinta",
"finial", "euphon", "auxin", "voiced"
);

@hosts = (
"neofetal", "theonomy", "panicked", "securely", "palgat", "rejoice",
"teagle", "unkeyed", "calor", "overpick", "runefolk", "trend",
"nunship", "leveling", "messe", "baetuli", "bossing", "mystic",
"cnida", "premove", "brassily", "fossiled", "fibril", "marooner",
"pataka", "bailee", "futurism", "tropate", "stuffer", "boost",
"portitor", "tussah", "goatskin", "clition", "antiwit", "scind",
"ruggedly", "chummer", "sloan", "mescal", "redub", "cozily",
"drawout", "matin", "acetated", "mustang", "shuck", "bruscus",
"yummy", "swiney", "snubby", "handrail", "centimo", "wind", "dog",
"magic", "wonder"
);

@queuechar = split(//,"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx");

# Specify different possible responses

%help = (
	"sendmail" => '"214-2.0.0 This is sendmail version 8.12.9\n214-2.0.0 Topics:\n214-2.0.0       HELO    EHLO    MAIL    RCPT    DATA\n214-2.0.0       RSET    NOOP    QUIT    HELP    VRFY\n214-2.0.0       EXPN    VERB    ETRN    DSN     AUTH\n214-2.0.0 For more info use \"HELP <topic>\".\n214-2.0.0 To report bugs in the implementation send email to\n214-2.0.0       sendmail-bugs\@sendmail.org.\n214-2.0.0 For local information send email to Postmaster at your site.\n214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helperror = (
	"sendmail" => '"504 5.3.0 HELP topic \"$helpask\" unknown"',
	"postfix" => '"502 Error: command not implemented"'
);

%helpexpn = (
	"sendmail" => '"214-2.0.0 EXPN <recipient>
214-2.0.0       Expand an address.  If the address indicates a mailing
214-2.0.0       list, return the contents of that list.
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helpverb = (
	"sendmail" => '"214-2.0.0 VERB
214-2.0.0       Go into verbose mode.  This sends 0xy responses that are
214-2.0.0       not RFC821 standard (but should be)  They are recognized
214-2.0.0       by humans and other sendmail implementations.
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helpetrn = (
	"sendmail" => '"214-2.0.0 ETRN [ <hostname> | \@<domain> |
214-2.0.0       Run the queue for the specified <hostname>, or
214-2.0.0       all hosts within a given <domain>, or a specially-named
214-2.0.0       <queuename> (implementation-specific).
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helpdsn = (
	"sendmail" => '"214-2.0.0 MAIL FROM: <sender> [ RET={ FULL | HDRS} ] [ ENVID=<envid> ]
214-2.0.0 RCPT TO: <recipient> [ NOTIFY={NEVER,SUCCESS,FAILURE,DELAY} ]
214-2.0.0                    [ ORCPT=<recipient> ]
214-2.0.0       SMTP Delivery Status Notifications.
214-2.0.0 Descriptions:
214-2.0.0       RET     Return either the full message or only headers.
214-2.0.0       ENVID   Sender\'s \"envelope identifier\" for tracking.
214-2.0.0       NOTIFY  When to send a DSN. Multiple options are OK, comma-
214-2.0.0               delimited. NEVER must appear by itself.
214-2.0.0       ORCPT   Original recipient.
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helpauth = (
	"sendmail" => '"214-2.0.0 AUTH mechanism [initial-response]
214-2.0.0       Start authentication.
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helprset = (
	"sendmail" => '"214-2.0.0 RSET
214-2.0.0       Resets the system.
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helpnoop = (
	"sendmail" => '"214-2.0.0 NOOP
214-2.0.0       Do nothing.
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helpquit = (
	"sendmail" => '"214-2.0.0 QUIT
214-2.0.0       Exit sendmail (SMTP).
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helphelp = (
	"sendmail" => '"214-2.0.0 HELP [ <topic> ]
214-2.0.0       The HELP command gives help info.
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);
%helpvrfy = (
	"sendmail" => '"214-2.0.0 VRFY <recipient>
214-2.0.0       Verify an address.  If you want to see what it aliases
214-2.0.0       to, use EXPN instead.
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helpdata = (
	"sendmail" => '"214-2.0.0 DATA
214-2.0.0       Following text is collected as the message.
214-2.0.0       End with a single dot.
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helphelo = (
	"sendmail" => '"214-2.0.0 HELO <hostname>
214-2.0.0       Introduce yourself.
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helpehlo = (
	"sendmail" => '"214-2.0.0 EHLO <hostname>
214-2.0.0       Introduce yourself, and request extended SMTP mode.
214-2.0.0 Possible replies include:
214-2.0.0       SEND            Send as mail                    [RFC821]
214-2.0.0       SOML            Send as mail or terminal        [RFC821]
214-2.0.0       SAML            Send as mail and terminal       [RFC821]
214-2.0.0       EXPN            Expand the mailing list         [RFC821]
214-2.0.0       HELP            Supply helpful information      [RFC821]
214-2.0.0       TURN            Turn the operation around       [RFC821]
214-2.0.0       8BITMIME        Use 8-bit data                  [RFC1652]
214-2.0.0       SIZE            Message size declaration        [RFC1870]
214-2.0.0       VERB            Verbose                         [Allman]
214-2.0.0       CHUNKING        Chunking                        [RFC1830]
214-2.0.0       BINARYMIME      Binary MIME                     [RFC1830]
214-2.0.0       PIPELINING      Command Pipelining              [RFC1854]
214-2.0.0       DSN             Delivery Status Notification    [RFC1891]
214-2.0.0       ETRN            Remote Message Queue Starting   [RFC1985]
214-2.0.0       STARTTLS        Secure SMTP                     [RFC2487]
214-2.0.0       AUTH            Authentication                  [RFC2554]
214-2.0.0       ENHANCEDSTATUSCODES     Enhanced status codes   [RFC2034]
214-2.0.0       DELIVERBY       Deliver By                      [RFC2852]
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helpmail = (
	"sendmail" => '"214-2.0.0 MAIL FROM: <sender> [ <parameters> ]
214-2.0.0       Specifies the sender.  Parameters are ESMTP extensions.
214-2.0.0       See \"HELP DSN\" for details.
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%helprcpt = (
	"sendmail" => '"214-2.0.0 RCPT TO: <recipient> [ <parameters> ]
214-2.0.0       Specifies the recipient.  Can be used any number of times.
214-2.0.0       Parameters are ESMTP extensions.  See \"HELP DSN\" for details.
214 2.0.0 End of HELP info"',
	"postfix" => '"502 Error: command not implemented"'
);

%vrfy = (
	"sendmail" => '"250 2.1.5 <$realuser>"',
	"postfix" => '"252 <$realuser>"'
);

%vrfyerror = (
	"sendmail" => '"501 5.5.2 Argument required"',
	"postfix" => '"501 Syntax: VRFY address"'
);

%vrfynouser = (
	"sendmail" => '"550 5.1.1 $vrfyuser... User unknown"',
	"postfix" => '"252 <$vrfyuser>"'
);

%rset = (
	"sendmail" => '"250 2.0.0 Reset state"',
	"postfix" => '"250 Ok"'
);

%noop = (
	"sendmail" => '"250 2.0.0 OK"',
	"postfix" => '"250 Ok"'
);

%received = (
	"sendmail" => '"Received: from $you ($srcname [$srcipaddress])\n\tby $hostname (8.12.9/8.11.3) with ESMTP id $queuenr\n\tfor <$recipient>; $datum"',
	"postfix" => '"Received: from $you ($srcname [$srcipaddress])\n\tby $hostname (Postfix) with ESMTP id $queuenr\n\tfor <$recipient>; $datum"',
);

%welcome = (
	"sendmail" => '"220 $hostname ESMTP Sendmail 8.12.9/8.11.3; $datum"',
	"postfix"  => '"220 $hostname ESMTP Postfix"'
);

%ehlos = (
	"sendmail" => '"250-".$hostname." Hello ".$srcname." [".$srcipaddress."], pleased to meet you\n250-ENHANCEDSTATUSCODES\n250-PIPELINING\n250-EXPN\n250-VERB\n250-8BITMIME\n250-SIZE 5000000\n250-DSN\n250-ETRN\n250-DELIVERBY\n250 HELP"',
	"postfix" => '"250-".$hostname."\n250-PIPELINING\n250-SIZE 10240000\n250-ETRN\n250 8BITMIME"'
);

%helos = (
	"sendmail" => '"250-".$hostname." Hello ".$srcname." [".$srcipaddress."], pleased to meet you"',
	"postfix" => '"250-".$hostname'
);

%heloerror = (
	"sendmail" => '"501 5.0.0 helo requires domain address"',
	"postfix" => '"501 Syntax: HELO hostname"'
);

%ehloerror = (
	"sendmail" => '"501 5.0.0 ehlo requires domain address"',
	"postfix" => '"501 Syntax: EHLO hostname"'
);

%errors = (
	"sendmail" => '"500 5.5.1 Command unrecognized: \"".$cmd."\""',
	"postfix" => '"502 Error: command not implemented"'
);

%mailfrom = (
	"sendmail" => '"250 2.1.0 ".$sender."... Sender ok"',
	"postfix" => '"250 Ok"'
);

%mailfromerror = (
	"sendmail" => '"503 5.5.0 Sender already specified"',
	"postfix" => '"503 Error: nested MAIL command"'
);

%timeout = (
	"sendmail" => '"451 4.4.1 timeout waiting for input during message collect"',
	"postfix" => '"421 Error: timeout exceeded"'
);

%rcptto = (
	"sendmail" => '"250 2.1.5 ".$recipient."... Recipient ok"',
	"postfix" => '"250 Ok"'
);

%rcpttoerror = (
	"sendmail" => '"503 5.0.0 Need MAIL before RCPT"',
	"postfix" => '"503 Error: need MAIL command"'
);

%data = (
	"sendmail" => '"354 Enter mail, end with \".\" on a line by itself"',
	"postfix" => '"354 End data with <CR><LF>.<CR><LF>"'
);

%datanomail = (
	"sendmail" => '"503 5.0.0 Need MAIL command"',
	"postfix" => '"503 Error: need RCPT command"'
);

%datanorcpt = (
	"sendmail" => '"503 5.0.0 Need RCPT (recipient)"',
	"postfix" => '"554 Error: no valid recipients"'
);

%quit = (
	"sendmail" => '"221 ".$hostname." closing connection"',
	"postfix" => '"221 Bye"'
);

%dot = (
	"sendmail" => '"250 2.0.0 ".$queuenr." Message accepted for delivery"',
	"postfix" => '"250 Ok: queued as ".$queuenr'
);

#
# DNS Reverse Lookup
#

sub reverse_lookup {
    my $ipaddress = shift(@_);
    my $res = Net::DNS::Resolver->new;
    my ($query, $hostname);

    $query = $res->query("$ipaddress", "PTR");

    if (!$query) {
	return ("");
    }

    $hostname= ($query->answer)[0]->rdatastr;
    $hostname =~ s/\.$//;

    return ($hostname);
}

#
# Run the SMTP server protocol to receive one email
#

sub receive_email {
  @recipients = ();
  $cmd = "";
  $realuser = "";
  $gotsender = 0;
  $gotrecipient = 0;
  $gotdata = 0;
  $you = "unspecified";

# Tries to create realistic queue ID numbers
  if ($mailer eq "sendmail") {
    local ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime;
    $wday = $isdst = $yday = 0;
    $queuenr = $queuechar[$year % 60].$queuechar[$mon].$queuechar[$mday].$queuechar[$hour].$queuechar[$min].$queuechar[$sec];
    $queuenr = $queuenr . sprintf("%05d", int(rand(100000)));
  } else {
    $queuenr = sprintf("%04X%06X",
		       int(rand(65536)), int(rand(65536*256)));
  }

#
###  Finite State Machine Start
#

  alarm $alarmtime;
 LINE: while (<STDIN>) {
    alarm $alarmtime;
  s/[\r\n]*\Z//m;

  SWITCH: {
      if (/^helo(.*)$/i) {
	$you = $1;
	$you =~ s/^ *//;
	$you =~ s/ *$//;
	if (length($you) == 0) {
	  $line = eval "$heloerror{$mailer}";
	} else {
	  $line = eval "$helos{$mailer}";
	}
	printf("%s\n", $line);
	last SWITCH;
      }
      if (/^ehlo(.*)$/i) {
	$you = $1;
	$you =~ s/^ *//;
	$you =~ s/ *$//;
	if (length($you) == 0) {
	  $line = eval "$ehloerror{$mailer}";
	} else {
	  $line = eval "$ehlos{$mailer}";
	}
	printf("%s\n", $line);
	last SWITCH;
      }
      if (/^mail from:(.*)/i) {
	if (! $gotsender) {
	  $sender = $1;
	  $sender =~ s/^ *//;
	  $sender =~ s/ *$//;
	  @parameters = split(/\s+/, $sender);
	  $sender = $parameters[0];
	  $line = eval "$mailfrom{$mailer}";
	  printf("%s\n", $line);
	  $gotsender = 1;

	  $sender =~ s/<(.*)>/$1/;
	} else {
	  $line = eval "$mailfromerror{$mailer}";
	  printf("%s\n", $line);
	}
	last SWITCH;
      }
      if (/^rcpt to:(.*)/i) {
	if ($gotsender) {
	  $recipient = $1;
	  $recipient =~ s/^ *//;
	  $recipient =~ s/ *$//;
	  $line = eval "$rcptto{$mailer}";
	  printf("%s\n", $line);
	  $gotrecipient = 1;

	  $recipient =~ s/<(.*)>/$1/;
	  push @recipients, $recipient;
	} else {
	  $line = eval "$rcpttoerror{$mailer}";
	  printf("%s\n", $line);
	}
	last SWITCH;
      }
      if (/^data(\s|$)/i) {
	if (! $gotsender) {
	  $line = eval "$datanomail{$mailer}";
	  printf("%s\n", $line);
	  last SWITCH;
	}
	if (! $gotrecipient) {
	  $line = eval "$datanorcpt{$mailer}";
	  printf("%s\n", $line);
	  last SWITCH;
	}
	
	$line = eval "$data{$mailer}";
	printf("%s\n", $line);
	$gotdata = 1;
	last LINE;
      }
      if (/^help(\s.*|$)/i) {
	$helpask = $1;
	$helpask =~ s/^\s+//;
	if ($helpask =~ /mail/) {
	  $line = eval "$helpmail{$mailer}";
	} elsif ($helpask =~ /rcpt/) {
	  $line = eval "$helprcpt{$mailer}";
	} elsif ($helpask =~ /helo/) {
	  $line = eval "$helphelo{$mailer}";
	} elsif ($helpask =~ /ehlo/) {
	  $line = eval "$helpehlo{$mailer}";
	} elsif ($helpask =~ /data/) {
	  $line = eval "$helpdata{$mailer}";
	} elsif ($helpask =~ /rset/) {
	  $line = eval "$helprset{$mailer}";
	} elsif ($helpask =~ /noop/) {
	  $line = eval "$helpnoop{$mailer}";
	} elsif ($helpask =~ /quit/) {
	  $line = eval "$helpquit{$mailer}";
	} elsif ($helpask =~ /help/) {
	  $line = eval "$helphelp{$mailer}";
	} elsif ($helpask =~ /vrfy/) {
	  $line = eval "$helpvrfy{$mailer}";
	} elsif ($helpask =~ /expn/) {
	  $line = eval "$helpexpn{$mailer}";
	} elsif ($helpask =~ /verb/) {
	  $line = eval "$helpverb{$mailer}";
	} elsif ($helpask =~ /etrn/) {
	  $line = eval "$helpetrn{$mailer}";
	} elsif ($helpask =~ /dsn/) {
	  $line = eval "$helpdsn{$mailer}";
	} elsif ($helpask =~ /auth/) {
	  $line = eval "$helpauth{$mailer}";
	} elsif ($helpask =~ /^$/) {
	  $line = eval "$help{$mailer}";
	} else{
	  $line = eval "$helperror{$mailer}";
	}
	printf("%s\n", $line);
	last SWITCH;
      }
      if (/^noop(\s|$)/i) {
	$line = eval "$noop{$mailer}";
	printf("%s\n", $line);
	last SWITCH;
      }
      if (/^vrfy(\s.*|$)/i) {
	$vrfyuser = $1;
	$vrfyuser =~ s/^\s+//;
	if (length($vrfyuser) == 0) {
	  $line = eval "$vrfyerror{$mailer}";
	} else{
	  if ($vrfyuser =~ /\@.*\./) {
	    $realuser = $vrfyuser;
	    $line = eval "$vrfy{$mailer}";
	  } else {
	    $line = eval "$vrfynouser{$mailer}";
	  }
	}
	printf("%s\n", $line);
	last SWITCH;
      }
      if (/^rset(\s|$)/i) {
	$line = eval "$rset{$mailer}";
	printf("%s\n", $line);
	return;
      }
      if (/^quit(\s|$)/i) {
	$line = eval "$quit{$mailer}";
	printf("%s\n", $line);
	exit (0);
      }
      # Nothing
	  $cmd = $_;
	  $line = eval "$errors{$mailer}";
	  printf("%s\n", $line);
      }
    }
	
 exit unless $gotdata;

      $gotdot = 0;
      $inbody = 0;
      @headers = ();
      @body = ();

# Insert necessary headers
      push @headers, "Return-Path: <$sender>";
      $line = eval "$received{$mailer}";
      push @headers, "$line";

# Now we are going to receive the email
    LINE: while (<STDIN>) {
	alarm $alarmtime;
	$line = $_;
	$line =~ s/[\r\n]*\Z//m;

	if ($line eq ".") {
	  $gotdot = 1;
	  last LINE;
	}
	if ($inbody == 0 && $line =~ /^$/) {
	    $inbody = 1;
	} else {
		push @headers, $line if !$inbody;
		push @body, $line if $inbody;
	}	
      }

      exit unless $gotdot;
      alarm 0;

      $line = eval "$dot{$mailer}";
      printf("%s\n", $line);

      $recipientlist = join(", ", @recipients);

      $number = write_email($sender, $recipient, \@headers, \@body);
      queue_email($sender, $recipient, \@headers, \@body)
	  if $queuemode && $number < 2;
      razor_email($sender, $recipient, \@headers, \@body)
	  if $razormode;
      report_email($reportemail, $sender, $recipient, \@headers, \@body)
	  if $reportemail and $#recipients < 4;
}

sub next_filename {
	my $dir = shift(@_);

	$count = -1;
	open(HANDLE, "$dir/.count") or $count = 0;
	if ($count == -1) {
	  $count = <HANDLE>;
	  chomp $count;
	  if (!($count =~ /^[0-9]+$/)) {
	    $count = 0;
	  }
	  close(HANDLE)
	}

	$count++;

	open(HANDLE, ">$dir/.count") or die "Cannot open count $dir/.count";
	print HANDLE "$count";
	close(HANDLE);

	$ueberdir = int($count / 1000);

	if (! -d "$dir/d$ueberdir") {
	  mkdir("$dir/d$ueberdir");
	}

	return ("d$ueberdir/$count");
}

#
# Queue email
#
sub queue_email {
    my ($sender, $recipient, $refheaders, $refbody) = @_;
    my ($boundary);
    my %mail;
    my ($header, $body);

    $queuedir = "$mailstore/queue";
    open(LOCK, ">>$queuedir/.lock")
	or die "Can not open lock file: $queuedir/.lock";
    flock(LOCK, LOCK_EX);

    $filename = next_filename($queuedir);

    open HANDLE, ">$queuedir/$filename"
	or die "Can not open $queuedir/$filename";

    flock(LOCK, LOCK_UN);
    close LOCK;

    print HANDLE "host: $dstipaddress\n";
    print HANDLE "helo: $hostname\n";
    print HANDLE "mail from: $sender\n";
    for $name (@recipients) {
	print HANDLE "rcpt to: $name\n";
    }
    print HANDLE "data\n";

    for $name (@$refheaders) {
	print HANDLE "$name\n";
    }
    print HANDLE "\n";
    for $name (@$refbody) {
	print HANDLE "$name\n";
    }

    print STDERR "Queued email from $srcipaddress:$sender for future delivery";

    close(HANDLE);
}

#
# Razor email
#
sub razor_email {
    my ($sender, $recipient, $refheaders, $refbody) = @_;
    my $razor = Razor2::Client::Agent->new("razor-report");
    my ($text, $ident, $objects, $sigs, @msg, %config);

    if (not $razor) {
	warn "Could not create Razor-Report";
	return;
    }

    %config = (
	       debug => 0,
	       foreground => 0,
	       config => $razorhome
    );

    $razor->{opt} = \%config;
    $razor->do_conf()
	or die "Could not configure Razor: $razor->errstr";

    $ident = $razor->get_ident
	or die "Could not get Razor identification: $razor->errstr";

    $text = "";

    # Extra headers
    # X-Envelope-{TO,FROM,CONNECT,HELO}
    $text .= "X-Envelope-To: $recipientlist\n";
    $text .= "X-Envelope-From: $sender\n";
    $text .= "X-Envelope-Connect: $srcipaddress\n";
    $text .= "X-Envelope-Helo: $you\n";

    for $name (@$refheaders) {
	$text .= "$name\n";
    }
    $text .= "\n";
    for $name (@$refbody) {
	$text .= "$name\n";
    }

    @msg = (\$text);
    $objects = $razor->prepare_objects(\@msg)
	or die "Razor error in prepare_objects: $razor->errstr";

    $razor->get_server_info()
	or die "Razor error in get_server_info: $razor->errstr";

    $sigs = $razor->compute_sigs($objects)
	or die "Razor error in compute_sigs: $razor->errstr";

    $razor->connect()
	or die "Razor error in connect: $razor->errstr";
    $razor->authenticate($ident)
	or die "Razor error in authenticate: $razor->errstr";
    $razor->report($objects)
	or die "Razor error in report: $razor->errstr";
    $razor->disconnect()
	or die "Razor error in disconnect: $razor->errstr";

    print STDERR "Reported email from $srcipaddress:$sender to Razor";

    close(HANDLE);
}

#
# Notify someone of a new email
#

sub report_email {
    my ($emailaddr, $sender, $recipient, $refheaders, $refbody) = @_;
    my ($boundary);
    my %mail;
    my ($header, $body);

    $header = "";
    for $name (@$refheaders) {
	$header .= "$name\n";
    }
    $body = "";
    for $name (@$refbody) {
	$body .= "$name\n";
    }

    $boundary = "====" . sprintf("%08x", int(rand(65536 * 65536))) . "====";

    %mail = (
	     "from" => "$emailaddr",
	     "to" => "$emailaddr",
	     "subject" => "Email Report: $srcipaddress: $sender, $recipient",
	     'content-type' => "multipart/alternative; boundary=\"$boundary\""
	    );

    $boundary = '--'.$boundary;

    $mail{"body"} = <<_EOF_;
$boundary
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: 8bit

Honeyd\'s spam trap has captured an email. It is very likely to be spam.
The original captured email has been attached to this message.

Src IP: $srcipaddress
Dst IP: $dstipaddress
Mailer: $mailer
Date: $datum
Helo: $you
Sender: $sender
Recipient: $recipientlist

$boundary
Content-Type: message/rfc822
Content-Description: original message
Content-Disposition: attachment
Content-Transfer-Encoding: 8bit

$header

$body
$boundary--
_EOF_

  sendmail(%mail) || print STDERR "Error sending mail: $Mail::Sendmail::error";
  return ($Mail::Sendmail::error);
}

#
#  Store Email in Email cache
#

sub write_email {
    my ($sender, $recipient, $refheaders, $refbody) = @_;
    my @headers = ();
    my @body = ();

    for $name (@$refheaders) {
	push @headers, $name;
    }
    for $name (@$refbody) {
	push @body, $name;
    }

    open(LOCK, ">>$maildrop/.lock")
      or die "Can not open lock file: $maildrop/.lock";
    flock(LOCK, LOCK_EX);

    $filename = next_filename($maildrop);

    die "Can not open $maildrop/$filename"
	unless open HANDLE, ">$maildrop/$filename";

    flock(LOCK, LOCK_UN);
    close(LOCK);

    for $name (@headers) {
	print HANDLE "$name\n";
    }
    print HANDLE "\n";
    for $name (@body) {
	print HANDLE "$name\n";
    }
    close HANDLE;

    print STDERR "$sender -> $recipientlist: $srcipaddress: Nr $filename\n";

    $datum =~ s/ +/ /g;
    # Create a log file
    open(LOG, ">>$mailstore/logfile")
      or die "Can not open $mailstore/logfile";
    flock(LOG, LOCK_EX);
    seek(LOG, 0, 2);
    print LOG "$datum: $sender -> $recipientlist: $srcipaddress: Nr $filename\n";
    flock(LOG, LOCK_UN);
    close(LOG);

    return ($filename);
}

# Main program
# Unbuffered
$| = 1;

# Alarm handler
$dstipaddress = $ENV{HONEYD_IP_DST};
$dstipaddress = "127.0.0.1" unless $dstipaddress;
$srcipaddress = $ENV{HONEYD_IP_SRC};
$srcipaddress = "127.0.0.1" unless $srcipaddress;
$srcdirectory = $srcipaddress;
$srcdirectory =~ s/\./\//g;

# Randomize Results
$none = 0;
@nrs = split(/\./, $dstipaddress);
for $nr (@nrs) {
    $none *= 257;
    $none += $nr;
}
$ntwo = 0;
@nrs = split(/\./, $srcipaddress);
pop @nrs;	# Only source network matters.
push @nrs, "0";
for $nr (@nrs) {
    $ntwo *= 256;
    $ntwo += $nr;
}

$nthree = 0;
if (not $hostname eq "") {
    for $nr (split(//, $hostname)) {
	$nthree += ord($nr);
    }
}

srand($none ^ $ntwo + $nthree);

$maildrop = "$mailstore/$srcdirectory";

die "Cache directory $mailstore does not exist" unless -d $mailstore;

# Create queue directory if necessary
if ( ! -d "$mailstore/queue") {
    die "Cannot create $mailstore/queue" unless mkdir "$mailstore/queue";
}

$srcname = "";

$number = rand(10);
if ($number % 2) {
    $mailer = "sendmail";
} else {
    $mailer = "postfix";
}

# Install Alarm Handler
# Give him a prompt
local $SIG{ALRM} = sub {
	$line = eval "$timeout{$mailer}";
	print "$line\n";
	exit;
};

$datum = strftime "%a, %e %b %Y %H:%M:%S %z (%Z)", localtime;
# Sendmail removes double spaces in the date, postfix does not
$datum =~ s/ +/ /g if $mailer eq "sendmail";
chomp $datum;
$hostname = $hosts[int(rand($#hosts))].".".$domains[int(rand($#domains))].".com"
    if $hostname eq "";

$line = eval "$welcome{$mailer}";
printf("%s\n", $line);

unless ( eval "use Mail::Sendmail 0.75; 1" )
{
    die "Please install Mail::Sendmail, Version 0.75 or greater";
}

unless ( eval "use Net::DNS; 1" )
{
    die "Please install Net::DNS";
}

# Check for razor

if ($razormode) {
    unless ( eval "use Razor2::Client::Agent; 1" )
    {
	warn "Razor2::Client::Agent is not available";
	$razormode = 0;
    }
}

# Create directory hierarchy
if ( ! -d "$maildrop" ) {
    @dirlevel = split(/\//, "$srcdirectory");
    $where = "$mailstore";
 LINE: for $level (@dirlevel) {
	$where = $where . "/$level";
	if ( -d $where) {
	    next LINE;
	}
	die "Cannot create $where" unless mkdir "$where";
    }
}

# Start the state machine

$srcname = reverse_lookup("$srcipaddress");

srand;

while (1) {
    receive_email;
}
