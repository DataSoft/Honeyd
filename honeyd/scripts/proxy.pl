#!/usr/bin/perl
#
# Spam Bait and Analyzer for Honeyd
#
# Copyright 2003 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
# For the license refer to the main source code of Honeyd.
use warnings;

unless ( eval "use Net::DNS; 1" )
{
    die "Please install Net::DNS";
}

$execprg = shift @ARGV;
$execargs = join(" ", @ARGV);
$execargs =~ s/\@/\\\\\\\@/g;	# Escape @ in email address if given.

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
# Main
#

$connectionfailed = <<_EOF_;
HTTP/1.0 503 Connect failed
Content-Type: text/html

<html>
<head>
<title>Internet Junkbuster: Connect failed</title>
</head>
<body bgcolor="#f8f8f0" link="#000078" alink="#ff0022" vlink="#787878">
<h1><center><strong>Internet J<small>UNK<i><font color="red">BUSTER</font></i></small></strong></center></h1>TCP connection to 'xmagic_magicx' failed: Operation not permitted.
<br></body>
</html>
_EOF_
$connectionestablished = <<_EOF_;
HTTP/1.0 200 Connection established
Proxy-Agent: IJ/2.0.2

_EOF_
$connectionbad = <<_EOF_;
HTTP/1.0 400 Invalid header received from browser

_EOF_
$connectioninvalid = <<_EOF_;
HTTP/1.0 400 Invalid header received from browser

_EOF_

$| = 1;

$srcip = "127.0.0.1";
$srcip = $ENV{HONEYD_SRC_IP} if $ENV{HONEYD_SRC_IP};


while (<STDIN>) {
    s/[\r\n]*\Z//m;  # remove trailing newlines

    if (/^CONNECT (.*) HTTP/i) {
	@what = split(/:/, $1);
    LINE: while (<STDIN>) {
	    s/[\r\n]*\Z//m;  # remove trailing newlines
	    if (length $_ == 0) {
		last LINE;
	    }
	}
	
	$host = $what[0];
	$port = $what[1];

	if (not $port eq "25") {
	    $connectionfailed =~ s/xmagic_magicx/$host:$port/gm;
	    print $connectionfailed;
	    exit;
	}
	# Check if the host is an IP address or not
	if ($host =~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
	    $hostname = reverse_lookup($host);
	} elsif ($host =~ /.*\.(edu|com|org)$/) {
	    $hostname = $host;
	} else {
	    $hostname = "";
	}

	$execargs = "-h $hostname ".$execargs unless $hostname eq "";

	print $connectionestablished;
	print STDERR "$srcip->$host:$port: $execargs";
	eval "exec \"$execprg $execargs\"";
	exit;
    } elsif (/^GET (.*) HTTP/i) {
	$host = $1;
    LINE: while (<STDIN>) {
	    s/[\r\n]*\Z//m;  # remove trailing newlines
	    if (length $_ == 0) {
		last LINE;
	    }
	}
	print $connectioninvalid;
	exit;
    } else {
	print $connectionbad;
	exit;
    }
}
