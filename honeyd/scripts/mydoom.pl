#! /usr/bin/perl -T
#-*-Perl-*-
#
# $Id: mydoom.pl,v 1.1 2004/03/16 17:02:09 provos Exp $
#
# mydoom.pl -- experimental Perl script, that works with honeyd, to
# emulate the backdoor installed by the Mydoom virus.  It saves
# uploaded files and also logs attempts to use the Mydoom backdoor
# proxy capability (socks4).
#
# Copyright (c) 2004 Klaus Steding-Jessen <jessen@nic.br>
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

(my $program_name = $0) =~ s@.*/@@;

use strict;
use warnings;
use Getopt::Std;
use Fcntl qw(:flock);
use POSIX qw(strftime);
use File::Path;

######################################################################

my %option = ();
getopts('Vhdl:t:', \%option);

my $version='0.6';

# unbuffered output.
$| = 1;

# set PATH.
$ENV{'PATH'} = '/bin:/usr/bin:/usr/sbin';

######################################################################
# configuration defaults -- some of them can be changed via
# command line options.

# logdir and logfile.
my $logdir = '/var/mydoom';
my $logfile = $logdir . '/' . 'logfile';

# timeout limit, in seconds.
my $timeout = 60;

# upload file size limit.
my $MAX_UPLOAD_FILESIZE = 15 * 1024 * 1024;

my $BUFFER_SIZE = 1500;

######################################################################
# mydoom constants.

my $SOCKS_VERSION = 0x04;
my $MYDOOM_UPLOAD = 0x85;
my $MYDOOM_MAGIC  = 0x133C9EA2;

######################################################################

# display usage if requested.
show_usage() if ($option{'h'});

# display version if requested.
show_version() if ($option{'V'});

# get logdir, if provided.
if (defined($option{'l'})) {
    if ($option{'l'} =~ /^([\w\.\/-]+)$/) {
        $logdir = $1;
        $logfile = $logdir . '/' . 'logfile';
    } else {
        show_usage();
    }
}

# get timeout.  If not provied use default value.
if (defined($option{'t'})) {
    if ($option{'t'} =~ /^(\d+)$/) {
        $timeout = $1;
    } else {
        show_usage();
    }
}

# get srchost, dsthost, srcport and dstport from the environment
# variables set by honeyd.

my $srchost = '127.0.0.1';
if (defined($ENV{'HONEYD_IP_SRC'}) &&
    $ENV{'HONEYD_IP_SRC'} =~ /^(\d+\.\d+\.\d+\.\d+)$/) {
    $srchost = $1;
}

my $dsthost = '127.0.0.1';
if (defined($ENV{'HONEYD_IP_DST'}) &&
    $ENV{'HONEYD_IP_DST'} =~ /^(\d+\.\d+\.\d+\.\d+)$/) {
    $dsthost = $1;
}

my $srcport = 0;
if (defined($ENV{'HONEYD_SRC_PORT'}) &&
    $ENV{'HONEYD_SRC_PORT'} =~ /^(\d+)$/) {
    $srcport = $1;
}

my $dstport = 0;
if (defined($ENV{'HONEYD_DST_PORT'}) &&
    $ENV{'HONEYD_DST_PORT'} =~ /^(\d+)$/) {
    $dstport = $1;
}

######################################################################
# main.

# install SIGALRM handler.
$SIG{ALRM} = sub {
    my $msg = sprintf("timed out after %d seconds", $timeout);
    logentry($logfile, $msg);
    die("$program_name: $msg\n");
    exit 0;
};

alarm $timeout;

logentry($logfile, sprintf("connection from %s:%d to %s:%d",
                           $srchost, $srcport, $dsthost, $dstport));

# read stdin from honeyd.
my $nread;
while ($nread = sysread(STDIN, my $buffer, $BUFFER_SIZE)) {

    # debug.
    logentry($logfile, sprintf("DEBUG: %d byte(s) read", $nread)) if ($option{'d'});

    # upload attempt.
    if (unpack("C", $buffer) == $MYDOOM_UPLOAD) {
            logentry($logfile, sprintf("file upload attempt from %s:%d",
                                       $srchost, $srcport));
            mydoom_upload($buffer);

    # socks4.
    } elsif (unpack("C", $buffer) == $SOCKS_VERSION) {

        logentry($logfile, sprintf("DEBUG: mydoom socks4: %s",
                                   data2hex($buffer))) if ($option{'d'});
        mydoom_socks4($buffer);

    # unknown data.
    } else {
        logentry($logfile, sprintf("unknown command: %s", data2hex($buffer)));
    }

    alarm $timeout;
}

if (!defined($nread)) {
    logentry($logfile, "ERROR: sysread: $!");
}

alarm 0;

logentry($logfile, "DEBUG: exiting") if ($option{'d'});

exit 0;

######################################################################
# handles socks4 connection attempts.  Returns a "request rejected or failed"
# code to the client.
sub mydoom_socks4 {

    my ($buffer) = @_;
    my $read = length($buffer);

    # socks4: http://www.socks.nec.com/protocol/socks4.protocol
    #
    # CONNECT request:
    #   VN      1 byte  socks version (4)
    #   CD      1 byte  command code (1 = connect)
    #   DSTPORT 2 bytes destination port
    #   DSTIP   4 bytes destination address
    #   USERID  variable(not used here)
    #   NULL1   byte
    #
    # +----+----+----+----+----+----+----+----+----+----+....+----+
    # | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
    # +----+----+----+----+----+----+----+----+----+----+....+----+
    #    1    1      2              4           variable       1
    #
    # reply:
    #
    # +----+----+----+----+----+----+----+----+
    # | VN | CD | DSTPORT |      DSTIP        |
    # +----+----+----+----+----+----+----+----+
    #     1    1      2              4
    #
    # VN is the version of the reply code and should be 0. CD is the result
    # code with one of the following values:
    #
    # 90: request granted
    # 91: request rejected or failed
    # 92: request rejected becasue SOCKS server cannot connect to
    #     identd on the client
    # 93: request rejected because the client program and identd
    #     report different user-ids

    my ($vn, $cd, $dstport, $dstaddr) = unpack("CCnA4x", $buffer);

    if (($cd == 1) && ($read == 9)) {
        my $dsthost = join('.', unpack('C4', $dstaddr));

        logentry($logfile,sprintf("socks4 connect request: dst host: %s, dst port: %d", $dsthost, $dstport));

        # return a request "rejected or failed" code.
        my $nwrite = syswrite(STDOUT, pack("CCnA4",
                                           0, 91, $dstport, $dstaddr));

        if (defined($nwrite)) {

            logentry($logfile, "DEBUG: rejected code sent back to client: $nwrite byte(s) written") if $option{'d'};

        } else {
            logentry($logfile, "ERROR: syswrite: $!");
        }

    } else {
        logentry($logfile, sprintf("socks4 command code: %02X", $cd));
    }

    return 0;
}
######################################################################
# handle upload file requests.
sub mydoom_upload {

    my ($buffer) = @_;
    my $read = length($buffer);

    # data may arrive in one big chunk or 1 + 4 + the rest bytes.

    if ($read == 1) {
       # we need another read.

        $nread = sysread(STDIN, my $buffer, 4);
        if (!defined($nread)) {
            logentry($logfile, "ERROR: sysread: $!");
            die("$program_name: sysread: $!\n");
        }

        $read += $nread;
        logentry($logfile, sprintf("DEBUG: %d byte(s) read", $nread))
            if ($option{'d'});

        if (($nread == 4) && (unpack("N", $buffer) == $MYDOOM_MAGIC)) {
            # ok, know comes the data.
            $nread = sysread(STDIN, my $buffer, $BUFFER_SIZE);
            if (!defined($nread)) {
                logentry($logfile, "ERROR: sysread: $!");
                die("$program_name: sysread: $!\n");
            }
            $read += $nread;
            logentry($logfile, sprintf("DEBUG: %d byte(s) read", $nread))
                if ($option{'d'});

        } else {
            logentry($logfile, sprintf("unknown upload signature: %s",
                                       data2hex($buffer)));
            return 0;
        }

    } else {
       # one big chunk.
        my ($first, $magic) = unpack("CN", $buffer);
        if (defined($magic) && ($magic == $MYDOOM_MAGIC)) {

            $buffer = substr($buffer, 5);

        } else {
            logentry($logfile, sprintf("unknown upload signature: %s",
                                       data2hex($buffer)));
            return 0;
        }
    }

    # Create directory hierarchy (adapted from smtp.pl).
    my $srchostdir = $srchost;
    $srchostdir =~ s/\./\//g;
    my $upload_dir = "$logdir/$srchostdir/$srcport";
    my $filename = "FILE.$$";  # use PID as extension.

    if (! -d "$upload_dir" ) {
        eval { mkpath($upload_dir) };
        if ($@) {
            logentry($logfile, "ERROR: $upload_dir: $@");
            die("$program_name: $upload_dir: $@");
        }
    }

    my $upload_file = "$upload_dir/$filename";

    if (!defined(open(UPLOAD_FILE, ">$upload_file"))) {
        logentry($logfile, "ERROR: $upload_file: $!");
        die("$program_name: $upload_file: $!\n");
    }

    # save first chunk.
    my $written = 0;
    if (!defined($written = syswrite(UPLOAD_FILE, $buffer))) {
        logentry($logfile, "ERROR: $upload_file: $!");
        die("$program_name: $upload_file: $!\n");
    }

    # read/save the rest of the file.
    my $uploaded = $written;
    do {
        $nread = sysread(STDIN, my $buffer, $BUFFER_SIZE);
        if (!defined($nread)) {
            logentry($logfile, "ERROR: sysread: $!");
            die("$program_name: sysread: $!\n");
        }

        $read += $nread;
        logentry($logfile, sprintf("DEBUG: %d byte(s) read", $nread))
            if ($option{'d'});

        $written = syswrite(UPLOAD_FILE, $buffer, $nread);
        if (!defined($written)) {
            logentry($logfile, "ERROR: $upload_file: $!");
            die("$program_name: $upload_file: $!\n");
        }

        $uploaded += $written;
        alarm $timeout;

    } while ($nread && ($uploaded < $MAX_UPLOAD_FILESIZE));

    close(UPLOAD_FILE);
    logentry($logfile, sprintf("file uploaded to %s, %d byte(s) written",
                               $upload_file, $uploaded));

    if ($uploaded >= $MAX_UPLOAD_FILESIZE) {
        logentry($logfile, "upload limit reached, exiting");
        exit(0);
    }

    return 0;
}
######################################################################
# create a log entry.
sub logentry {
    my ($logfile, $msg) = @_;

    my $datum = strftime "%F %T %z", localtime;
    my $pid = $$;

    open(LOG, ">>$logfile") ||
	die "$program_name: $logfile: $!\n";
    flock(LOG, LOCK_EX);
    seek(LOG, 0, 2);

    printf LOG ("%s: %s[%d]: %s\n", $datum, $program_name, $pid, $msg);

    flock(LOG, LOCK_UN);
    close(LOG);

}
######################################################################
# return a hexa representation of data.
sub data2hex {
    my ($data) = @_;
    my $hex;

    $hex = unpack("H*", $data);
    if (defined($hex)) {
        $hex =~ s/../0x$& /g;
        $hex =~ s/ $//g;
    } else {
        $hex = "";
    }
    return $hex;
}
######################################################################
# print program usage and exit.
sub show_usage {
    print <<EOF;
Usage: $program_name [-Vdh] [-t timeout] [-l dir]
       -h             display this help and exit.
       -V             display version number and exit.
       -d             debug mode.
       -t timeout     timeout, in seconds.  Default is $timeout.
       -l dir         log dir.  Default is $logdir.
EOF

    exit 0;
}
######################################################################
# print program version and exit.
sub show_version {
    printf("%s %s\n", $program_name, $version);
    exit 0;
}
######################################################################

# mydoom.pl ends here.
