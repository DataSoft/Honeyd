#! /usr/bin/perl -T
#-*-Perl-*-
#
# $Id: kuang2.pl,v 1.1 2004/12/31 18:54:22 provos Exp $
#
# kuang2.pl -- Honeyd module that emulates the backdoor installed by the
#              Kuang2 virus.
#
# Copyright (c) 2003, 2004 Klaus Steding-Jessen
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

=head1 NAME

kuang2.pl -- Honeyd module that emulates the backdoor installed by the Kuang2 virus.

=head1 SYNOPSIS

kuang2.pl [-Vh] [-d] [-f file]

=head1 DESCRIPTION

Start kuang2.pl as a Honeyd service.

The options are as follows:

=over 6

=item -V

Display version number and exit.

=item -h

Display this help and exit.

=item -d

debug mode.

=item -f file

configuration file.

=back

=head1 SEE ALSO

Honeyd.

=head1 AUTHOR

Klaus Steding-Jessen <jessen@nic.br>

=head1 AVAILABILITY

The latest version of kuang2.pl is available from
http://www.honeynet.org.br/tools/

=cut

######################################################################

(my $program_name = $0) =~ s@.*/@@;

use strict;
use warnings;
use Getopt::Std;
use Fcntl qw(:flock);
use POSIX qw(strftime);
use File::Path;
use File::Basename;

unless (eval "use Digest::SHA1; 1") {
    die "$program_name: Please install Digest::SHA1\n";
}

######################################################################

my %option = ();
getopts('Vhdf:n', \%option);

my $version='0.2';

# unbuffered output.
$| = 1;

# set PATH.
$ENV{'PATH'} = '/bin:/usr/bin:/usr/sbin';

######################################################################
# configuration defaults -- can be changed via configuration file.
# parameter, regex value and default value.

my %checksum = ();
my %conf = (
            "logdir" => {
                regex => '[\w\.-\/]+',
                value => '/var/kuang2' },
            "timeout" => {
                regex => '\d+',
                value => 30 },
            "num_drives" => {
                regex => '\d+',
                value => 1 },
            "computer_name" => {
                regex => '[\w\s]+',
                value => 'MY COMPUTER' },
            "max_upload_size"  => {
                regex => '\d+',
                value =>  15728640 },
            );

######################################################################
# kuang2 constants.

my $K2_BUFFER_SIZE =   1024;
my $K2_HELO =          0x324B4F59;
my $K2_ERROR =         0x52525245;
my $K2_DONE =          0x454E4F44;
my $K2_QUIT =          0x54495551;
my $K2_DELETE_FILE =   0x464C4544;
my $K2_RUN_FILE =      0x464E5552;
my $K2_FOLDER_INFO =   0x464E4946;
my $K2_DOWNLOAD_FILE = 0x464E5744;
my $K2_UPLOAD_FILE =   0x46445055;
my $K2_UPLOAD_FILE_2 = 0x0000687f;
my $K2_UPLOAD_FILE_3 = 0x00007620;
my $K2_UPLOAD_FILE_4 = 0x00004820;

######################################################################

# display usage if requested.
show_usage() if ($option{'h'});

# display version if requested.
show_version() if ($option{'V'});

# parse config options from the configuration file, if requested.
if (defined($option{'f'})) {
    my ($confref) = process_config_file($option{'f'}, \%conf);
    %conf = %{$confref};
}

# logfile.
my $logfile = $conf{'logdir'}{'value'} . '/' . 'logfile';

######################################################################
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
    my $msg = sprintf("timed out after %d seconds", $conf{'timeout'}{'value'});
    logentry($logfile, $msg);
    die("$program_name: $msg\n");
    exit 0;
};

alarm $conf{'timeout'}{'value'};

logentry($logfile, sprintf("connection from %s:%d to %s:%d",
                           $srchost, $srcport, $dsthost, $dstport));

# send the initial K2_HELO to the client.
my $name_size = $K2_BUFFER_SIZE - 8;
my $nwrite = syswrite(STDOUT, pack("IIZ$name_size", $K2_HELO,
                                   $conf{'num_drives'}{'value'},
                                   $conf{'computer_name'}{'value'}));

logentry($logfile, "DEBUG: K2_HELO sent to client")
    if ($option{'d'});

# read stdin from honeyd -- loop reading commands from the client.
my $nread;
while ($nread = sysread(STDIN, my $buffer, $K2_BUFFER_SIZE)) {

    # debug.
    #logentry($logfile, "DEBUG: $nread byte(s) read") if ($option{'d'});

    my $cmd = (unpack("I*", $buffer));
    if (defined($cmd)) {
        #logentry($logfile, sprintf("DEBUG: cmd: 0x%02X", $cmd))
        #    if ($option{'d'});
    } else {
        logentry($logfile, sprintf("data: %s", data2hex($buffer)));
        next;
    }

    # process commands sent from the kuang2 client.
    if ($cmd == $K2_UPLOAD_FILE) {
        k2_upload_file($buffer, 0);

    } elsif ($cmd == $K2_DOWNLOAD_FILE) {
        k2_download_file($buffer);

    } elsif ($cmd == $K2_QUIT) {
        logentry($logfile, "K2_QUIT received, exiting");
        exit 0;

    } elsif ($cmd == $K2_DELETE_FILE) {
        k2_delete_file($buffer);

    } elsif ($cmd == $K2_RUN_FILE) {
        k2_run_file($buffer);

    } elsif ($cmd == $K2_FOLDER_INFO) {
        k2_folder_info($buffer);

    } elsif (($cmd == $K2_UPLOAD_FILE_2) ||
             ($cmd == $K2_UPLOAD_FILE_3) ||
             ($cmd == $K2_UPLOAD_FILE_4)) {
        # different upload procotol.
        k2_upload_file($buffer, -1);

    } else {
        # unknown command.
        logentry($logfile, sprintf("unknown command: %s", data2hex($buffer)));

        my $nwrite = syswrite(STDOUT, pack("I", $K2_ERROR));
        logentry($logfile, "DEBUG: K2_ERROR sent to client") if ($option{'d'});
    }
    alarm $conf{'timeout'}{'value'};
}

logentry($logfile, "ERROR: sysread: $!") if (!defined($nread));

alarm 0;

logentry($logfile, "exiting");
exit 0;

######################################################################
# handle upload file requests.
sub k2_upload_file {
    my ($buffer, $flag) = @_;

    my ($cmd, $filesize, $filename);
    if ($flag == 0) {
        ($cmd, $filesize, $filename) = unpack("IIZ*", $buffer);
    } else {
        $filesize = -1;
        ($cmd, $filename) = unpack("IZ*", $buffer);
    }

    # check if unpack() succeeded.
    if (!defined($cmd) || !defined($filesize) || !defined($filename)) {
        my $msg = "unpack() error";
        logentry($logfile, $msg);
        die("$program_name: $msg\n");
    }

    # untaint filename.
    if ($filename =~ /^([\w\\\/\.:]+)$/) {
        $filename = $1;
    }

    if ($flag == 0) {
        # we only accept files >0 and <= MAX_UPLOAD_FILESIZE bytes long.
        if (!(($filesize > 0) &&
              ($filesize <= $conf{'max_upload_size'}{'value'}))) {
            my $nwrite = syswrite(STDOUT, pack("I", $K2_ERROR));
            logentry($logfile, "DEBUG: K2_ERROR sent to client")
                if ($option{'d'});
            my $msg = sprintf("illegal file size: %ld byte(s)", $filesize);

            logentry($logfile, $msg);
            die("$program_name: $msg\n");
        }
    }

    if ($flag == 0) {
        logentry($logfile,
                 sprintf("cmd received: K2_UPLOAD_FILE, file: %s, size: %d byte(s)",
                         quotemeta($filename), $filesize));
    } else {
        logentry($logfile,
                 sprintf("cmd received: K2_UPLOAD_FILE (ALT), file: %s",
                         quotemeta($filename)));
    }

    # ack the K2_UPLOAD_FILE request.
    my $nwrite = syswrite(STDOUT, pack("I", $K2_DONE));
    logentry($logfile, "DEBUG: K2_DONE sent to client") if ($option{'d'});

    # keep only the basename component and also remove the drive part
    # (c:\\, d:\\, etc) on MSDOS/Win filenames.
    fileparse_set_fstype("MSWin32");
    $filename = basename($filename);

    # create directory hierarchy (adapted from smtp.pl).
    my $srchostdir = $srchost;
    $srchostdir =~ s/\./\//g;
    my $upload_dir = "$conf{'logdir'}{'value'}/$srchostdir/$srcport";

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

    # read the file.
    my $uploaded = 0;
    my $nread = 0;
    do {

        $nread = sysread(STDIN, my $buffer, $K2_BUFFER_SIZE);
        #logentry($logfile, "DEBUG: $nread byte(s) read") if ($option{'d'});

        my $nwrite = syswrite(UPLOAD_FILE, $buffer, $nread);
        $uploaded += $nwrite;

        if ($uploaded > $conf{'max_upload_size'}{'value'}) {
            my $msg = sprintf("ERROR: upload limit exceeded: %ld byte(s)",
                              $uploaded);
            logentry($logfile, $msg);
            die("$program_name: $msg\n");
        }

        alarm $conf{'timeout'}{'value'};
    } while (($uploaded != $filesize) && $nread);

    close(UPLOAD_FILE);

    # if filesize is known, check if it matches uploaded size.
    if (($flag == 0) && ($uploaded != $filesize)) {
        logentry($logfile,
                 sprintf("sizes don't match, filesize: %ld, uploaded: %ld",
                         $filesize, $uploaded));
    }

    # check for empty uploaded files.
    if (-z $upload_file) {
        my $msg = sprintf("ERROR: %s is empty", $upload_file);
        logentry($logfile, $msg);
        die("$program_name: $msg\n");
    }

    # determine the SHA-1 of uploaded file.
    if (!defined(open(UPLOAD_FILE, "$upload_file"))) {
        logentry($logfile, "ERROR: $upload_file: $!");
        die("$program_name: $upload_file: $!\n");
    }
    my $ctx = Digest::SHA1->new;
    $ctx->addfile(*UPLOAD_FILE);
    my $digest = $ctx->hexdigest;
    close(UPLOAD_FILE);

    logentry($logfile,
             sprintf("file uploaded to %s, size: %d byte(s), SHA-1: %s",
                     $upload_file, -s $upload_file, $digest));

    # we're done.
    $nwrite = syswrite(STDOUT, pack("I", $K2_DONE));
    logentry($logfile, "DEBUG: K2_DONE sent to client") if ($option{'d'});

    return 0;
}
######################################################################
# handle run file requests.
sub k2_run_file {
    my ($buffer) = @_;

    my ($cmd, $filename) = unpack("IZ*", $buffer);

    # check if unpack() succeeded.
    if (!defined($cmd) || !defined($filename)) {
        my $msg = "unpack() error";
        logentry($logfile, $msg);
        die("$program_name: $msg\n");
    }

    # untaint filename.
    if ($filename =~ /^([\w\\\/\.:]+)$/) {
        $filename = $1;
    }

    logentry($logfile,
             sprintf("cmd received: K2_RUN_FILE, file: %s",
                     quotemeta($filename)));

    # we're done.
    $nwrite = syswrite(STDOUT, pack("I", $K2_DONE));
    logentry($logfile, "DEBUG: K2_DONE sent to client") if ($option{'d'});

    return 0;
}
######################################################################
# handle delete file requests.
sub k2_delete_file {
    my ($buffer) = @_;

    my ($cmd, $filename) = unpack("IZ*", $buffer);

    # check if unpack() succeeded.
    if (!defined($cmd) || !defined($filename)) {
        my $msg = "unpack() error";
        logentry($logfile, $msg);
        die("$program_name: $msg\n");
    }

    # untaint filename.
    if ($filename =~ /^([\w\\\/\.:]+)$/) {
        $filename = $1;
    }

    logentry($logfile,
             sprintf("cmd received: K2_DELETE_FILE, file: %s",
                     quotemeta($filename)));

    # return an error to the client.
    $nwrite = syswrite(STDOUT, pack("I", $K2_ERROR));
    logentry($logfile, "DEBUG: K2_ERROR sent to client") if ($option{'d'});

    return 0;
}
######################################################################
# handle download file requests.
sub k2_download_file {
    my ($buffer) = @_;

    my ($cmd, $filename) = unpack("IZ*", $buffer);

    # check if unpack() succeeded.
    if (!defined($cmd) || !defined($filename)) {
        my $msg = "unpack() error";
        logentry($logfile, $msg);
        die("$program_name: $msg\n");
    }

    # untaint filename.
    if ($filename =~ /^([\w\\\/\.:]+)$/) {
        $filename = $1;
    }

    logentry($logfile,
             sprintf("cmd received: K2_DOWNLOAD_FILE (init), file: %s",
                     quotemeta($filename)));

    # return an error to the client.
    $nwrite = syswrite(STDOUT, pack("I", $K2_ERROR));
    logentry($logfile, "DEBUG: K2_ERROR sent to client") if ($option{'d'});

    return 0;
}
######################################################################
# handle folfer info requests.
sub k2_folder_info {
    my ($buffer) = @_;

    my ($cmd, $filename) = unpack("IZ*", $buffer);

    # check if unpack() succeeded.
    if (!defined($cmd) || !defined($filename)) {
        my $msg = "unpack() error";
        logentry($logfile, $msg);
        die("$program_name: $msg\n");
    }

    # untaint filename.
    if ($filename =~ /^([\w\\\/\.:]+)$/) {
        $filename = $1;
    }

    logentry($logfile,
             sprintf("cmd received: K2_FOLDER_INFO, start: %s",
                     quotemeta($filename)));

    # return an error to the client.
    $nwrite = syswrite(STDOUT, pack("I", $K2_ERROR));
    logentry($logfile, "DEBUG: K2_ERROR sent to client") if ($option{'d'});

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

    my $hex = unpack("H*", $data);
    if (defined($hex)) {
        $hex =~ s/../0x$& /g;
        $hex =~ s/ $//g;
    } else {
        $hex = "";
    }

    return $hex;
}
######################################################################
# process the configuration file.  Exits in case of error.
sub process_config_file {
    my ($filename, $confref) = @_;
    my %conf = %{$confref};

    # filename: words, numbers, '-', '/' and '.' are ok.
    if ($filename =~ /^([\w\.\-\/]+)$/) {
        $filename = $1;
    } else {
        $filename = quotemeta($filename);
        die("$program_name: invalid filename: $filename\n");
    }

    open(CONF, "$filename") ||
        die ("$program_name: can't open $filename: $!\n");

    while (my $line = <CONF>) {
        chomp($line);
        next if ($line =~ /^$|^\s*$|^\s*#/); # skip comments and empty lines.
        foreach my $key (keys %conf) {
            if ($line =~ /^$key\s*[=:]\s*($conf{$key}{'regex'})\s*$/) {
                $conf{$key}{'value'} = $1;
                last;
            } elsif ($line =~ /^$key\s*/) {
                die("$program_name: invalid parameter: $line\n");
            }
        }
    }
    close(CONF);
    return \%conf;
}
######################################################################
# print program usage and exit.
sub show_usage {
    print <<EOF;
Usage: $program_name [-Vh] [-d] [-f file]
       -h             display this help and exit.
       -V             display version number and exit.
       -d             debug.
       -f file        configuration file.
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

# kuang2.pl ends here.
