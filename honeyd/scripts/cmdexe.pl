#!/usr/bin/perl -T
#-*-Perl-*-
#
# $Id: cmdexe.pl,v 1.1 2004/12/31 18:54:23 provos Exp $
#
# cmdexe.pl -- experimental Perl script, that works with honeyd, to
#              emulate a cmd.exe prompt. It logs the command line
#              entered. Non-printable characters are logged in
#              hexdump format.
#
# Copyright (c) 2004 Luiz Eduardo Roncato Cordeiro <cordeiro@nic.br>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#    - Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    - Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials provided
#      with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

######################################################################

(my $PROGNAME = $0) =~ s@.*/@@;

use strict;
use warnings;
use Getopt::Std;
use Fcntl qw(:flock);
use POSIX qw(strftime);
use File::Path;

######################################################################

my %option = ();
getopts('Vhdl:t:p:n:', \%option);

#For CVS , use following line
my $VERSION=sprintf("%d.%02d", q$Revision: 1.1 $ =~ /(\d+)\.(\d+)/);

# unbuffered output.
$| = 1;

# set PATH.
$ENV{'PATH'} = '/bin:/usr/bin:/usr/sbin';

######################################################################
# configuration defaults -- some of them can be changed via
# command line options.

# logfile.
my $logdir = '/var/cmdexe';
my $logfile = $logdir . '/' . 'logfile';

# timeout limit, in seconds.
my $timeout = 60;

# echo on or off
my $echo = 1;

# hexdump length
my $hexdumplen = 8;

# ip number regex
my $ipregex = "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." .
              "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." .
              "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." .
              "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";

# default personality
my $personality = "winxp";

my $personalities = "win95|win98|winme|winnt|win2000|winxp";

my %info =
(
  win95 =>
  {
    systemname => "Microsoft(R) Windows 95",
    copyright =>  "   (C) Copyright Microsoft Corp 1981-1996",
    error => "bad command or file name"
  },
  win98 =>
  {
    systemname => "Microsoft(R) Windows 98",
    copyright =>  "   (C) Copyright Microsoft Corp 1981-1998",
    error => "Bad command or file name"
  },
  winme =>
  {
    systemname => "Microsoft(R) Windows Millenium",
    copyright =>  "   (C) Copyright Microsoft Corp 1981-1999",
    error => "bad command or file name"
  },
  winnt =>
  {
    systemname => "Microsoft(R) Windows NT(TM)",
    copyright =>  "(C) Copyright 1985-1996 Microsoft Corp.",
    error => "The name specified is not recognized as an\n".
             "internal or external command, operable program or batch file."
  },
  win2000 =>
  {
    systemname => "Microsoft Windows 2000 [Version 5.00.2195]",
    copyright =>  "(C) Copyright 1985-2000 Microsoft Corp.",
    error => "The name specified is not recognized as an\n".
             "internal or external command, operable program or batch file."
  },
  winxp =>
  {
    systemname => "Microsoft Windows XP [Version 5.1.2600]",
    copyright => "(C) Copyright 1985-2001 Microsoft Corp.",
    error => "The name specified is not recognized as an\n".
             "internal or external command, operable program or batch file."
  }
);

######################################################################

# display usage if requested.
show_usage() if ($option{'h'});

# display version if requested.
show_version() if ($option{'V'});

# get logdir, if provided.
if (defined($option{'l'}))
{
  if ($option{'l'} =~ /^([\w\.\/-]+)$/)
  {
    $logdir = $1;
    $logfile = $logdir . '/' . 'logfile';
  }
  else
  {
    show_usage();
  }
}

# get hexdump length.  If not provied use default value.
if (defined($option{'n'}))
{
  if ($option{'n'} =~ /^(\d+)$/)
  {
    $hexdumplen = $1;
  }
  else
  {
    show_usage();
  }
}


# get timeout.  If not provied use default value.
if (defined($option{'t'}))
{
  if ($option{'t'} =~ /^(\d+)$/)
  {
    $timeout = $1;
  }
  else
  {
    show_usage();
  }
}

# get personality.  If not provied use default value.
if (defined($option{'p'}))
{
  if ($option{'p'} =~ /^($personalities)$/)
  {
    $personality = $1;
  }
  else
  {
    show_usage();
  }
}

# get srchost, dsthost, srcport and dstport from the environment
# variables set by honeyd.

my $srchost = '127.0.0.1';
if (defined($ENV{'HONEYD_IP_SRC'}) &&
    $ENV{'HONEYD_IP_SRC'} =~ /^($ipregex)$/)
{
  $srchost = $1;
}

my $dsthost = '127.0.0.1';
if (defined($ENV{'HONEYD_IP_DST'}) &&
    $ENV{'HONEYD_IP_DST'} =~ /^($ipregex)$/)
{
  $dsthost = $1;
}

my $srcport = 0;
if (defined($ENV{'HONEYD_SRC_PORT'}) &&
    $ENV{'HONEYD_SRC_PORT'} =~ /^([0-9]{1,5})$/)
{
  $srcport = $1;
}

my $dstport = 0;
if (defined($ENV{'HONEYD_DST_PORT'}) &&
    $ENV{'HONEYD_DST_PORT'} =~ /^([0-9]{1,5})$/)
{
  $dstport = $1;
}



######################################################################
# main

# install SIGALRM handler.
$SIG{ALRM} = sub
{
  my $msg = sprintf("timed out after %d seconds", $timeout);
  logentry($logfile, $msg);
  die("\n$PROGNAME: $msg\n");
  exit 0;
};

alarm $timeout;

logentry($logfile, sprintf("connection from %s:%d to %s:%d",
                           $srchost, $srcport, $dsthost, $dstport));

printf("%s\n%s\n\n",
       $info{$personality}{systemname},
       $info{$personality}{copyright});

print "C:\\>";

# read stdin from honeyd.
while (<STDIN>) {
  chomp;
  
  $_ =~ s/\r$//; # extract the last 0x0A if it exists
  
  if ($_ =~ /[[:^print:]]/)
  {
    my @lines = hexdump($_);
    foreach my $line (@lines)
    {
      logentry($logfile, sprintf("hex: %s", $line));
    }
  }
  else
  {
    logentry($logfile, sprintf("cmd: %s", $_));
  }
  
  $echo = 0 if ($_ =~ /echo\s+off/i);
  $echo = 1 if ($_ =~ /echo\s+on/i);
  
  if ($_ =~ /^exit/i)
  {
      logentry($logfile, sprintf("exiting %s", $PROGNAME));
      exit 0;
  }
  
  print $info{$personality}{error} . "\n" if ($echo);
  
  print "\nC:\\>" if ($echo);

  alarm $timeout;
}

alarm 0;

logentry($logfile, "forced exit of cmdexe.pl (eg, ^C in a connection)");

exit 0;

######################################################################
# create a log entry.
sub logentry {
    my ($logfile, $msg) = @_;

    my $datum = strftime "%F %T %z", localtime;
    my $pid = $$;

    open(LOG, ">>$logfile") ||
        die "$PROGNAME: $logfile: $!\n";
    flock(LOG, LOCK_EX);
    seek(LOG, 0, 2);

    printf LOG ("%s: %s[%d]: %s\n", $datum, $PROGNAME, $pid, $msg);

    flock(LOG, LOCK_UN);
    close(LOG);
}

######################################################################
# return a hexa representation of data.
sub hexdump {
  my ($buffer) = @_;
  my @bytes = unpack('C*', $buffer);
  my $bufferlen = length $buffer;

  my @lines = ();  
  my $line = "";
  my $ascii = "";
  for (my $i=0; $i<$bufferlen; $i++)
  {
    $line .= sprintf('%0.2X ', $bytes[$i]);
    $ascii .= $bytes[$i] >= 32 && $bytes[$i] < 127 ? chr $bytes[$i] : '.';
    if ($i % $hexdumplen == $hexdumplen - 1 || $i == $bufferlen - 1)
    {
      $line .= '   ' x (($hexdumplen - 1) - ($i % $hexdumplen)) . '|' .$ascii;
      $line .= ' ' x (($hexdumplen - 1) - ($i % $hexdumplen)) . '|';
      push @lines, $line;
      $line = $ascii = "";
    }
  }
  return @lines;
}

######################################################################
# print program usage and exit.
sub show_usage {
    print <<EOF;
Usage: $PROGNAME [-Vdh] [-p personality] [-t timeout] [-l dir]
       -h             display this help and exit.
       -V             display version number and exit.
       -d             debug mode.
       -t timeout     timeout, in seconds.  Current is $timeout.
       -l dir         log dir.  Current is $logdir.
       -n length      hexdump length. Current is $hexdumplen.
       -p personality one of: win95, win98, winme, 
                              winnt, win2000, winxp
EOF

    exit 0;
}

######################################################################
# print program version and exit.
sub show_version {
    printf("%s %s\n", $PROGNAME, $VERSION);
    exit 0;
}

######################################################################

__END__
