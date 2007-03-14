#! /usr/bin/perl

# Dirs to be used
my $logdir = "/var/log/honeyd";
my $configdir = "/usr/local/share/honeyd";

# Default SNMP communities (if none specified in args)
my @default_communities = (	"public",
				"private",
                          );


#################################################################

use BER; # needed for proper snmp encoding get it with SNMP_Session
use SNMP_Session;
use Fcntl; #
use IO::Handle;

sub extractSNMP($);
sub oidcmp($$);

my $IP_SRC=$ENV{'HONEYD_IP_SRC'};
my $IP_DST=$ENV{'HONEYD_IP_DST'};
my $SRC_PORT=$ENV{'HONEYD_SRC_PORT'};
my $DST_PORT=$ENV{'HONEYD_DST_PORT'};
my $PERSONALITY=$ENV{'HONEYD_PERSONALITY'};

my @communities;

# Initializing stuff

if($#ARGV >= 0) { @communities = @ARGV; }
else { @communities = @default_communities; }

my $logfile = $logdir."/".$IP_SRC."-".$IP_DST.":snmp";
die "unable to open $logfile : $!\n" unless open(LOG,">>".$logfile);

LOG->autoflush(1);

my $configfile = $configdir."/".$IP_DST.".snmp";
my $defaultconfigfile = $configdir."/default.snmp";

if(!(-e $configfile)) {
	die "cannot find an appropriate configuration file in $configdir : $! \n" unless -e $defaultconfigfile;
         $configfile = $defaultconfigfile;
}

die "cannot open configuration file in $configfile : $! \n" unless open(FILE,$configfile);

# Getting Request

#my $flags = '';
#die "Couldn\'t get STDIN flags : $!\n" unless fcntl(STDIN, F_GETFL, $flags);
#$flags |= O_NONBLOCK;
#die "Can\'t have STDIN non-blocking : $!\n" unless fcntl(STDIN, F_SETFL, $flags);

#do {

	#my $request = '';

while(sysread(STDIN,$request,1024)) {

         #$request = <STDIN>;

	#if($request ne '') {

         	my $community_ok = 0;

		my ($community, $request_type, $request_id, $oids_ref) = extractSNMP($request);

		print LOG $community." - ".$request_type." - ".${@$oids_ref}[0]."\n";

                 foreach(@communities) {
                 	if($_ eq $community) { $community_ok = 1; break; }
                 }

                 if($community_ok) {

			my $oid = ${@$oids_ref}[0];
			my $answer = "";

                         # SNMP GET
			if($request_type eq "GET") {
				while($entry = <FILE>) {
					if($entry =~ /^\.$oid\s=\s(.*)/) { $answer = $1; chomp($answer); break; }
                 		}

                         # SNMP WALK
			} elsif($request_type eq "NEXT") {
				my $orig_oid = $oid;

				while($oid eq $orig_oid) {
                                 	$entry = <FILE>;
         				if(($tmp_oid,$trash,$answer) = $entry =~ /^((\.\d+)+)\s=\s(.*)/) {
                           			my $tmp_oid = substr $tmp_oid,1;
                                                 chomp($answer);
                           			if(oidcmp($tmp_oid,$oid)) { $oid = $tmp_oid; }
                           		}
                 		}

                         # SNMP SET -> Todo
			} elsif($request_type eq "SET") { ; }

                         if($request_type =~ /(GET|NEXT)/) {

				print LOG "Answering $oid : $answer\n";

				my $answer_type = "NULL";
				my $answer_value = "";

				if($answer =~ /^(STRING|INTEGER|OID|Timeticks|Gauge32|Counter32|Counter64|IpAddress):\s+(.*)/) {
                                 	$answer_type = $1;
                                         $answer_value = $2;
                                         chomp($answer_value);
                                 }

				my @answer_oid = split(/\./,$oid);
				my $encoded_answer_value;

				if($answer_type eq "STRING") { $encoded_answer_value = encode_string($answer_value); }
				elsif($answer_type eq "INTEGER") { $encoded_answer_value = encode_int($answer_value); }
                                 elsif($answer_type eq "OID") { my @tmp_oid = split(/\./,$answer_value); shift(@tmp_oid); $encoded_answer_value = encode_oid(@tmp_oid); }
                                 elsif($answer_type eq "Timeticks") { $encoded_answer_value = encode_timeticks($answer_value); }
                                 elsif($answer_type eq "Gauge32") { $encoded_answer_value = encode_gauge32($answer_value); }
                                 elsif($answer_type eq "Counter32") { $encoded_answer_value = encode_counter32($answer_value); }
                                 elsif($answer_type eq "Counter64") { $encoded_answer_value = encode_counter64($answer_value); }
                                 elsif($answer_type eq "IpAddress") { $answer_value =~ s/(\d+\.\d+\.\d+\.\d+)\D.*/$1/; $encoded_answer_value = encode_ip_address($answer_value); }

				my $encoded_answer = encode_sequence (
					encode_int ($snmp_version),
                     			encode_string ($community),
                                         encode_tagged_sequence(
						SNMP_Session::get_response,
         					encode_int ($request_id),
         					encode_int_0 (),
         					encode_int_0 (),
                                                 encode_sequence(
         						encode_sequence(
                                                 		encode_oid(@answer_oid),
                                                         	$encoded_answer_value
                                                         )
                                                 )
           				)
                                    );

				syswrite(STDIN,$encoded_answer);
                         }

		} else { print LOG "Wrong community ($community) submited\n"; }
#         }
}

exit;

sub extractSNMP ($) {

	my($request) = @_;

         my ($snmp_version, $comm, $rid, $errorstatus, $errorindex, $bindings);
	my $request_type = "NONE";
         my @oids;

	($snmp_version, $comm, $rid, $errorstatus, $errorindex, $bindings) = decode_by_template ($request, "%{%i%s%*{%i%i%i%@", SNMP_Session::get_request);
	if (defined $snmp_version) { $request_type = "GET"; }
         else {
		($snmp_version, $comm, $rid, $errorstatus, $errorindex, $bindings) = decode_by_template ($request, "%{%i%s%*{%i%i%i%@", SNMP_Session::getnext_request);
    		if (defined $snmp_version) { $request_type = "NEXT"; }
         	else {
			($snmp_version, $comm, $rid, $errorstatus, $errorindex, $bindings) = decode_by_template ($request, "%{%i%s%*{%i%i%i%@", SNMP_Session::set_request);
    			if (defined $snmp_version) { $request_type = "SET"; }
                 }
         }

         if($request_type =~ /(GET|NEXT)/) {

         	while($bindings ne '') {
         		($binding,$bindings) = &decode_sequence ($bindings);

                         my $l = length($binding);
                         my $ber_oid = substr $binding,2,$l-4;
                         my ($raw_oid) = BER::decode_oid($ber_oid);
                         push(@oids,BER::pretty_oid($raw_oid));

                 }
         }

         return ($comm,$request_type,$rid,\@oids);

}

sub oidcmp ($$) {

	my ($oid1,$oid2) = @_;

         my @oid1 = split(/\./,$oid1);
         my @oid2 = split(/\./,$oid2);

         #for(my $i=0; $i<6; $i++) { shift(@oid1); shift(@oid2); }

         while(my $tmp1 = shift(@oid1)) {

                 my $tmp2 = shift(@oid2);

                 if($tmp1 > $tmp2) { return 1; }
                 if($tmp1 < $tmp2) { return 0; }
         }

         return 0;
}




