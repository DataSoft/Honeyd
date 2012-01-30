#! /usr/bin/perl -T -w
#-*-Perl-*-
#
# Copyright (c) 2004 Lucio Henrique Franco (lucio@lac.inpe.br) and
#          Carlos Henrique Peixoto Caetano Chaves (cae@lac.inpe.br)
#
# All rights reserved.
#            Renato Archer Research Center (CenPRA)
#            Brazilian National Institute for Space Research (INPE)
#            Information System and Network Security Group
#            version 0.3 - Thu Apr 15 09:30:31 BRT 2004
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#    - Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    - Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#    - All advertising materials mentioning features or use of this
#      software must display the following acknowledgement:
#      This product includes software developed by Lucio Henrique
#      Franco and Carlos H. P. C. Chaves. CenPRA and INPE aren't
#      responsible by use or distribution of this material.
#    - Neither the name of the Research Center nor the names of its
#      contributors may be used to endorse or promote products
#      derived from this software without specific prior written
#      permission.
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
#

##########################################################################
### Modules used by this script

use strict;
use Getopt::Std;

our $program_name;
($program_name = $0) =~ s@.*/@@;

unless (eval "use Net::Netmask; 1") {
   die "$program_name: please install Net::Netmask.";
}

unless (eval "use GD; 1") {
   die "$program_name: please install GD.";
}

unless (eval "use GD::Graph::pie; 1") {
   die "$program_name: please install GD::Graph::pie.";
}

unless (eval "use GD::Graph::bars; 1") {
   die "$program_name: please install GD::Graph::bars.";
}

unless (eval "use GD::Graph::bars3d; 1") {
   die "$program_name: please install GD::Graph::bars3d.";
}

##########################################################################
### Program name, version and options

our %option = ();

getopts('c:hwV', \%option) || die "$program_name: cannot get options.\n";

our $honeydsum_version = '0.3';

##########################################################################
### Some global declarations

# set PATH for this script
$ENV{'PATH'} = '/bin:/usr/bin:/usr/local/bin';

# unbuffered output
$| = 1;

# IP regexp
our $IP_exp = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}';

# Timestmap regexp
our $timestamp_exp = '\d{4}\-\d{2}\-\d{2}\-\d{2}\:\d{2}\:\d{2}\.\d{4}';

# Time regexp
our $time = '\d+:\d+:\d+';

# used to read files from command line
our $cat   = '/bin/cat';
our $zcat  = '/usr/bin/zcat';
our $bzcat = '/usr/local/bin/bzcat';

# configuration file
our @honeyd_conf_files;
our $honeyd_conf = 0;
our $honeydsum_conf_file;

# output html dir/file
our $output_html_file;
our $output_html_dir;

# used to show icmp protocol
our ($proto_show) = 0;

# used to show the number of elements of top
our ($top_show) = 11;

# used to address sanitize
our @real_hp_net;
our @fake_hp_net;
our $real_hp_net_obj;
our $fake_hp_net_obj;
our @real_inst_net;
our @fake_inst_net;
our $real_inst_net_obj;
our $fake_inst_net_obj;

# used to graphics
our %graph_hp_a = ();
our %graph_hp_b = ();
our $person = 0;
our %graphics = ();

##########################################################################
### Checking arguments

# display version if requested
if (defined($option{V})) {
   &show_version;
}

# check if there are arguments
if ($#ARGV == -1 || defined($option{h})) {
   &show_usage;
}

##########################################################################
### Local variables for Main

my ($file, $viewer, $line);
my ($totalpkts, $tcppkts, $udppkts, $icmppkts);
my (
   $timestamp, $proto, $src_ip, $dst_ip,     $resource,
   $port,      $hour,  $bytes,  $nbr_src_ip, $nbr_dst_ip
);

my (@IP_list)    = ();
my (@NET_list)   = ();
my (@PORT_list)  = ();
my (@PROTO_list) = ();

my (%stat_hash)     = ();
my (%src_host_hash) = ();
my (%resource_hash) = ();
my (%hour_hash)     = ();
my (%icmp_b40_hash) = ();

my ($cnt, $dez, $uni);

# Print
my $ip_flag;
my ($total_connections)     = 0;
my (@total_resource)        = ();
my ($total_resource_number) = 0;
my ($total_ip)              = 0;
my $control                 = 0;
my $control_hp;

# Graphics information
our @ip_high   = ();
our @total_res = ();
our @total_ips = ();
our @total_con = ();

# HONEYD_CONF
our %honeyd_conf_conv  = ();
our %honeyd_conf_print = (
   'header' =>
"<table cellpadding=\"2\" cellspacing=\"1\" border=\"1\" style=\"text-align: left; width: 328px; height: auto;\">
  		        <tbody>
    				<tr>
      					<td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\" rowspan=\"1\" colspan=\"6\">
						<big style=\"color: rgb(255, 255, 102);\">
						<span style=\"font-weight: bold;\"><a name=\"honeypots_configuration\"></a>HONEYPOT'S CONFIGURATION</span>
						</big>
      					</td>
    				</tr>
    				<tr>
 					   <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\">
						   <big style=\"color: rgb(255, 255, 102);\">Operating System
						   </big>
      			   </td>
 					   <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\">
						   <big style=\"color: rgb(255, 255, 102);\">Default TCP Action
						   </big>
      			   </td>
 					   <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\">
						   <big style=\"color: rgb(255, 255, 102);\">Default UDP Action
						   </big>
      			   </td>
 					   <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\">
						   <big style=\"color: rgb(255, 255, 102);\">Default ICMP Action
						   </big>
      			   </td>
 					   <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\">
						   <big style=\"color: rgb(255, 255, 102);\">Ports
						   </big>
      			   </td>
 					   <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\">
						   <big style=\"color: rgb(255, 255, 102);\">IP Address
						   </big>
      			   </td>
    				</tr>"
);

$honeyd_conf_print{'foot'} = ("</tbody></table><hr>");

##########################################################################
###  Main

# Honeyd.conf
if (defined($option{'c'})) {
   $honeydsum_conf_file = $option{'c'};

   &parser_config_file($honeydsum_conf_file);
} else {
   warn("$program_name: you must inform honeydsum.conf file.\n");
   exit 1;
}

# Output as web page
if (defined($option{'w'})) {

   if (!($output_html_file = &check_filename($output_html_file))) {
      warn("$program_name: " . quotemeta($output_html_file) . " invalid file name.\n");
   }

   if ($output_html_file =~ /^(.*\/).*/) {
      $output_html_dir = $1;
   } else {
      $output_html_dir = "";
   }
   open(HTML_FILE, ">" . $output_html_file)
     || die("$program_name: cannot open file.\n");
   printf(HTML_FILE "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\n");
   printf(HTML_FILE "\"http://www.w3.org/TR/html4/strict.dtd\">\n");
   printf(HTML_FILE "<html>\n");
   printf(HTML_FILE "<head>\n");
   printf(HTML_FILE "<title>HONEYD's CONNECTIONS STATISTICS</title>\n");
   printf(HTML_FILE
"<meta http-equiv=\"content-type\" content=\"text/html;charset=iso-8859-1\">\n"
   );
   printf(HTML_FILE "<script type=\"text/javascript\">
function AbreInst(theURL,winName,features) {
  window.open(theURL,winName,features);
}
  </script>\n"
   );
   printf(HTML_FILE "</head>\n");
   printf(HTML_FILE "<body>\n");

   printf(HTML_FILE
"<table cellpadding=\"2\" cellspacing=\"1\" border=\"1\" style=\"text-align: left; height: auto; width: 316px;\">
                        <tbody>                   
                           <tr>\n"
   );
   if ($honeyd_conf) {
      printf(HTML_FILE
"<td style=\"vertical-align: top; text-align: center; background-color: rgb(204, 204, 204);\">
                                    <span style=\"font-weight: bold;\"><a href=\"#honeypots_configuration\">HONEYPOT'S CONFIGURATION</a>
                                    </span>
                                 <br>
                              </td>\n"
      );
   }

   printf(HTML_FILE
"          <td style=\"vertical-align: top; text-align: center; background-color: rgb(204, 204, 204);\">
                                    <span style=\"font-weight: bold;\"><a href=\"#honeypots_connections\">HONEYPOT'S CONNECTIONS</a>
                                    </span>
                                 <br>
                              </td>
<td style=\"vertical-align: top; text-align: center; background-color: rgb(204, 204, 204);\">
                                    <span style=\"font-weight: bold;\"><a href=\"#honeypots\">HONEYPOT'S</a>
                                    </span>
                                 <br>
                              </td>
<td style=\"vertical-align: top; text-align: center; background-color: rgb(204, 204, 204);\">
                                    <span style=\"font-weight: bold;\"><a href=\"#top_source\">Top %s Source Hosts</a>
                                    </span>
                                 <br>
                              </td>
<td style=\"vertical-align: top; text-align: center; background-color: rgb(204, 204, 204);\">
                                    <span style=\"font-weight: bold;\"><a href=\"#top_accessed\">Top %s Accessed Resources</a>
                                    </span>
                                 <br>
                              </td>
<td style=\"vertical-align: top; text-align: center; background-color: rgb(204, 204, 204);\">
                                    <span style=\"font-weight: bold;\"><a href=\"#top_icmp\">Top %s ICMP>40 bytes Senders</a>
                                    </span>
                                 <br>
                              </td>
<td style=\"vertical-align: top; text-align: center; background-color: rgb(204, 204, 204);\">
                                    <span style=\"font-weight: bold;\"><a href=\"#connections\">Connections per Hour</a>
                                    </span>
                                 <br>
                              </td>

                           </tr>
                           </tbody>
                           </table><hr>\n", ($top_show - 1), ($top_show - 1),
      ($top_show - 1)
   );

}

if (defined($option{'-'})) {
   push(@ARGV, "-");
}

# Erase hour hash
$dez = 48;
$uni = 48;
while (!($dez == 50 && $uni == 52)) {
   $hour_hash{ chr($dez) . chr($uni) } = 0;
   if ($uni == 57) {
      $dez++;
      $uni = 48;
   } else {
      $uni++;
   }
}

######################################
# Parser

$totalpkts = 0;
$tcppkts   = 0;
$udppkts   = 0;
$icmppkts  = 0;
foreach my $arg (@ARGV) {
   if (!($file = &check_filename($arg))) {
      $file = quotemeta($arg);
      warn("$program_name: $file invalid file name.\n");
      next;
   }

   if ($file =~ /\.bz2$/) {
      $viewer = $bzcat;
   } elsif ($file =~ /\.gz$/) {
      $viewer = $zcat;
   } else {
      $viewer = $cat;
   }

   my @viewer_args = ();
   push(@viewer_args, $file);
   my $pid = open(CHILD_TO_READ1, "-|");

   if (!$pid) {

      # child
      exec($viewer, @viewer_args)
        || die("$program_name: $viewer: cannot exec: $!\n");

      # never reached
   } else {

      # parent
      my $line_count = 0;

      while ($line = <CHILD_TO_READ1>) {
         $line_count++;
         chomp($line);

###
#2003-12-16-16:50:29.0837 tcp(6) - xxx.xxx.xxx.xxx 37604 yyy.yyy.yyy.yyy 23: 60 S
#2003-12-16-16:50:29.0863 tcp(6) - xxx.xxx.xxx.xxx 37608 yyy.yyy.yyy.yyy 23: 60 S [Linux 2.6 ]
#2003-12-16-16:50:32.0824 tcp(6) S xxx.xxx.xxx.xxx 37614 yyy.yyy.yyy.yyy 23 [Linux 2.6 ]
#2003-12-16-16:50:33.0388 tcp(6) E xxx.xxx.xxx.xxx 37614 yyy.yyy.yyy.yyy 23: 0 0
#2003-12-16-16:50:41.0267 tcp(6) S xxx.xxx.xxx.xxx 1938 yyy.yyy.yyy.yyy 8080 [Windows 2000 SP4]
#2003-12-16-16:50:42.0484 tcp(6) E xxx.xxx.xxx.xxx 1940 yyy.yyy.yyy.yyy 6588: 151 0
###

         if ($line =~
/^($timestamp_exp)\s+(tcp)\(6\)\s+([S|\-|E])\s($IP_exp)\s+\d{1,5}\s+($IP_exp)\s+(\d{1,5})+.*/
           )
         {

            unless ($3 eq "E") {
               $timestamp = $1;
               $proto     = $2;

               if ($#real_inst_net != -1) {
                  $src_ip = &sanitize_ip($4, \@real_inst_net, \@fake_inst_net);
               } else {
                  $src_ip = $4;
               }

               if ($#real_hp_net != -1) {
                  $dst_ip = &sanitize_ip($5, \@real_hp_net, \@fake_hp_net);
               } else {
                  $dst_ip = $5;
               }

               $resource = $6;

               if (
                  (($#IP_list == -1) || (&check_list($dst_ip, @IP_list)))
                  && (  ($#NET_list == -1)
                     || (&check_net_list($src_ip)))
                  && (  ($#PORT_list == -1)
                     || (&check_list($resource, @PORT_list)))
                  && (  ($#PROTO_list == -1)
                     || (&check_list($proto, @PROTO_list)))
                 )
               {

                  $totalpkts++;
                  $tcppkts++;

                  $nbr_src_ip = unpack "N", pack "C4", split /\./, $src_ip;
                  $nbr_dst_ip = unpack "N", pack "C4", split /\./, $dst_ip;

                  if (
                     !defined(
                        $stat_hash{$nbr_dst_ip}{$nbr_src_ip}{$proto}{$resource}
                     )
                    )
                  {
                     $stat_hash{$nbr_dst_ip}{$nbr_src_ip}{$proto}{$resource} =
                       0;
                  }
                  $stat_hash{$nbr_dst_ip}{$nbr_src_ip}{$proto}{$resource}++;

                  if (!defined($src_host_hash{$src_ip})) {
                     $src_host_hash{$src_ip} = 0;
                  }
                  $src_host_hash{$src_ip}++;

                  if (!defined($resource_hash{ $resource . "/" . $proto })) {
                     $resource_hash{ $resource . "/" . $proto } = 0;
                  }
                  $resource_hash{ $resource . "/" . $proto }++;

                  if ($timestamp =~ /^\d{4}\-\d{2}\-\d{2}\-(\d{2})\:.*$/) {
                     $hour = $1;
                     $hour_hash{$hour}++;
                  }
               }
            } else {
               next;
            }
         } elsif ($line =~
/^($timestamp_exp)\s+(udp)\(17\)\s+([S|\-|E])\s+($IP_exp)\s+\d{1,5}\s+($IP_exp)\s+(\d{1,5}).*/
           )
         {
###
#2003-10-03-21:46:40.0864 udp(17) - xxx.xxx.xxx.xxx 138 yyy.yyy.yyy.yyy 138: 229
#2003-12-17-19:41:19.002 udp(17) S xxx.xxx.xxx.xxx 53 yyy.yyy.yyy.yyy 53
#2003-12-17-19:42:19.017 udp(17) E xxx.xxx.xxx.xxx 53 yyy.yyy.yyy.yyy 53: 18 0
###
            unless ($3 eq "E") {
               $timestamp = $1;
               $proto     = $2;

               if ($#real_inst_net != -1) {
                  $src_ip = &sanitize_ip($4, \@real_inst_net, \@fake_inst_net);
               } else {
                  $src_ip = $4;
               }

               if ($#real_hp_net != -1) {
                  $dst_ip = &sanitize_ip($5, \@real_hp_net, \@fake_hp_net);
               } else {
                  $dst_ip = $5;
               }
               $resource = $6;

               if (
                     (($#IP_list == -1) || (&check_list($dst_ip, @IP_list)))
                  && (($#NET_list == -1) || (&check_net_list($src_ip)))
                  && (  ($#PORT_list == -1)
                     || (&check_list($resource, @PORT_list)))
                  && (  ($#PROTO_list == -1)
                     || (&check_list($proto, @PROTO_list)))
                 )
               {
                  $totalpkts++;
                  $udppkts++;

                  $nbr_src_ip = unpack "N", pack "C4", split /\./, $src_ip;
                  $nbr_dst_ip = unpack "N", pack "C4", split /\./, $dst_ip;

                  if (
                     !defined(
                        $stat_hash{$nbr_dst_ip}{$nbr_src_ip}{$proto}{$resource}
                     )
                    )
                  {
                     $stat_hash{$nbr_dst_ip}{$nbr_src_ip}{$proto}{$resource} =
                       0;
                  }
                  $stat_hash{$nbr_dst_ip}{$nbr_src_ip}{$proto}{$resource}++;

                  if (!defined($src_host_hash{$src_ip})) {
                     $src_host_hash{$src_ip} = 0;
                  }
                  $src_host_hash{$src_ip}++;

                  if (!defined($resource_hash{ $resource . "/" . $proto })) {
                     $resource_hash{ $resource . "/" . $proto } = 0;
                  }
                  $resource_hash{ $resource . "/" . $proto }++;

                  if ($timestamp =~ /^\d{4}\-\d{2}\-\d{2}\-(\d{2})\:.*$/) {
                     $hour = $1;
                     $hour_hash{$hour}++;
                  }
               }
            } else {
               next;
            }
         } elsif ($line =~
/^($timestamp_exp)\s+(icmp)\(1\)\s+\-\s+($IP_exp)\s+($IP_exp)\:\s+(\d{1,2})\(\d{1,2}\)\:\s+(\d+)/
           )
         {
###
#2003-09-13-00:00:15.0775 icmp(1) - xxx.xxx.xxx.xxx yyy.yyy.yyy.yyy: 8(0): 92
###
            $timestamp = $1;
            $proto     = $2;

            if ($#real_inst_net != -1) {
               $src_ip = &sanitize_ip($3, \@real_inst_net, \@fake_inst_net);
            } else {
               $src_ip = $3;
            }

            if ($#real_hp_net != -1) {
               $dst_ip = &sanitize_ip($4, \@real_hp_net, \@fake_hp_net);
            } else {
               $dst_ip = $4;
            }
            $resource = $5;
            $bytes    = $6;

            if (  (($#IP_list == -1) || (&check_list($dst_ip, @IP_list)))
               && (($#NET_list == -1)   || (&check_net_list($src_ip)))
               && (($#PORT_list == -1)  || (&check_list($resource, @PORT_list)))
               && (($#PROTO_list == -1) || (&check_list($proto, @PROTO_list))))
            {
               $totalpkts++;
               $icmppkts++;

               $nbr_src_ip = unpack "N", pack "C4", split /\./, $src_ip;
               $nbr_dst_ip = unpack "N", pack "C4", split /\./, $dst_ip;

               if (
                  !defined(
                     $stat_hash{$nbr_dst_ip}{$nbr_src_ip}{$proto}{$resource}
                  )
                 )
               {
                  $stat_hash{$nbr_dst_ip}{$nbr_src_ip}{$proto}{$resource} = 0;
               }
               $stat_hash{$nbr_dst_ip}{$nbr_src_ip}{$proto}{$resource}++;

               if (!defined($src_host_hash{$src_ip})) {
                  $src_host_hash{$src_ip} = 0;
               }
               $src_host_hash{$src_ip}++;

               if (!defined($resource_hash{ $resource . "/" . $proto })) {
                  $resource_hash{ $resource . "/" . $proto } = 0;
               }
               $resource_hash{ $resource . "/" . $proto }++;

               if ($timestamp =~ /^\d{4}\-\d{2}\-\d{2}\-(\d{2})\:.*$/) {
                  $hour = $1;
                  $hour_hash{$hour}++;
               }

               if ($bytes > 40) {
                  if (!defined($icmp_b40_hash{$src_ip})) {
                     $icmp_b40_hash{$src_ip} = 0;
                  }
                  $icmp_b40_hash{$src_ip}++;
               }
            }
         } else {
            warn("$program_name: unknown format: $line \n");
         }
      }    #end while
      close(CHILD_TO_READ1) || warn("$program_name: $viewer: exited $?\n");
   }    #end else
}    #end foreach ARGV

my %src_ip_hash;

if (defined($stat_hash{$nbr_dst_ip})) {
   %src_ip_hash = %{ $stat_hash{$nbr_dst_ip} };
} else {
   warn("$program_name: element not found!!!\n");
   if (defined($option{'w'})) {
      close(HTML_FILE);
   }
   exit 1;
}

if ($honeyd_conf) {
   foreach my $honeyd_conf_file (@honeyd_conf_files) {
      &ext_honeyd_conf($honeyd_conf_file);
   }
}

if (!defined($option{'w'})) {    # OUTPUT - TEXT

   printf("\n--------------------------------------\n");
   printf("Connection Counter\n");
   printf("--------------------------------------\n");
   printf("Total: %10d\n", $totalpkts);
   printf("  TCP: %10d\n", $tcppkts);
   printf("  UDP: %10d\n", $udppkts);
   printf(" ICMP: %10d\n", $icmppkts);
   printf("--------------------------------------\n\n");

   my $nbr_dst_ip_txt;
   my $dst_ip_txt;
   my $nbr_src_ip_txt;
   my $src_ip_txt;
   my $proto_txt;

   my $resource_txt;

   foreach $nbr_dst_ip_txt (sort { $a <=> $b } keys %stat_hash) {
      my %src_ip_hash_txt = %{ $stat_hash{$nbr_dst_ip_txt} };
      my $ip_flag_txt;
      my ($total_connections_txt)     = 0;
      my (@total_resource_txt)        = ();
      my ($total_resource_number_txt) = 0;
      my ($total_ip_txt)              = 0;

      $dst_ip_txt = join ".", unpack "C4", pack "N", $nbr_dst_ip_txt;

      printf("--------------------------------------\n");
      printf("Honeypot: %s\n", $dst_ip_txt);
      printf("--------------------------------------\n");
      printf("%-15s %9s %12s\n", "Source IP", "Resource", "Connections");

      foreach $nbr_src_ip_txt (sort { $a <=> $b } keys %src_ip_hash_txt) {
         $ip_flag_txt = 0;

         my %proto_hash_txt = %{ $src_ip_hash_txt{$nbr_src_ip_txt} };

         $src_ip_txt = join ".", unpack "C4", pack "N", $nbr_src_ip_txt;

         foreach $proto_txt (keys %proto_hash_txt) {
            my %resource_hash_txt = %{ $proto_hash_txt{$proto_txt} };

            foreach $resource_txt (sort { $a <=> $b } keys %resource_hash_txt) {
               $total_connections_txt =
                 $total_connections_txt + $resource_hash_txt{$resource_txt};
               push(@total_resource_txt, $resource_txt);
               if ($ip_flag_txt == 0) {
                  printf("%-15s %5s/%-5s %5d\n",
                     $src_ip_txt, $resource_txt, $proto_txt,
                     $resource_hash_txt{$resource_txt});
                  $ip_flag_txt = 1;
                  $total_ip_txt++;
               } else {
                  printf("%-15s %5s/%-5s %5d\n",
                     " ", $resource_txt, $proto_txt,
                     $resource_hash_txt{$resource_txt});
               }
            }
         }
      }

      my (%seen_txt) = ();
      my ($item_txt) = ();
      foreach $item_txt (@total_resource_txt) {
         $total_resource_number_txt++ unless $seen_txt{$item_txt}++;
      }

      printf("--------------------------------------\n");
      printf("%-15s %9s %12s\n", "IPs", "Resources", "Connections");
      printf("%-15s %9s %8s\n",
         $total_ip_txt, $total_resource_number_txt, $total_connections_txt);
      printf("--------------------------------------\n");
   }

   printf("\n\nTop %s Source Hosts\n\n", ($top_show - 1));
   printf("%-4s %-15s %9s\n", "Rank", "Source IP", "Connections");

   $cnt = 1;
   foreach $src_ip (
      sort { $src_host_hash{$b} <=> $src_host_hash{$a} }
      keys %src_host_hash
     )
   {
      printf("%-4d %-15s %8d\n", $cnt, $src_ip, $src_host_hash{$src_ip});
      $cnt++;
      if ($cnt == $top_show) {
         last;
      }
   }

   printf("\n\nTop %s Accessed Resources\n\n", ($top_show - 1));
   printf("%-4s %-11s %9s\n", "Rank", "Resource", "Connections");

   $cnt = 1;
   foreach $port (
      sort { $resource_hash{$b} <=> $resource_hash{$a} }
      keys %resource_hash
     )
   {
      printf("%-4d %-11s %8d\n", $cnt, $port, $resource_hash{$port});

      $cnt++;
      if ($cnt == $top_show) {
         last;
      }
   }

   if ($proto_show == 0 || $proto_show == 5 || $proto_show == 6) {
      printf("\n\nTop %s ICMP > 40 bytes Senders\n\n", ($top_show - 1));
      printf("%-4s %-15s %9s\n", "Rank", "Source IP", "Connections");

      $cnt = 1;
      foreach $src_ip (
         sort { $icmp_b40_hash{$b} <=> $icmp_b40_hash{$a} }
         keys %icmp_b40_hash
        )
      {
         printf("%-4d %-15s %8d\n", $cnt, $src_ip, $icmp_b40_hash{$src_ip});
         $cnt++;
         if ($cnt == $top_show) {
            last;
         }
      }
   }

   printf("\n\nConnections per Hour\n\n");
   printf("%-5s %9s\n", "Hour", "Connections");

   foreach $hour (sort { $a cmp $b } keys %hour_hash) {
      printf("%s:00 %8d\n", $hour, $hour_hash{$hour});
   }
} else {    # OUTPUT - HTML

   printf(HTML_FILE
"<table style=\"text-align: left; height: 262px; width: 652px;\" border=\"0\" cellspacing=\"3\" cellpadding=\"3\">
  <tbody>
    <tr>
      <td style=\"text-align: center; vertical-align: middle;\">\n"
   );

   printf(HTML_FILE
"<table cellpadding=\"2\" cellspacing=\"1\" border=\"1\" style=\"text-align: left; height: auto; width: 272px;\">
                        <tbody>
                           <tr>
                              <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\" rowspan=\"1\" colspan=\"2\">
                                 <big style=\"color: rgb(255, 255, 102);\">
                                    <span style=\"font-weight: bold;\"><a name=\"honeypots_connections\"></a>HONEYPOT'S CONNECTIONS
                                    </span>
                                 </big>
                                 <br>
                              </td>
                           </tr>
                           <tr>
                              <td style=\"vertical-align: top; background-color: rgb(153, 153, 153);\" rowspan=\"1\" colspan=\"2\">
                                 <span style=\"font-weight: bold;\">Connection Counter
                                 </span>
                                 <br>
                              </td>
                           </tr>\n"
   );
   printf(HTML_FILE "      <tr>
                              <td style=\"vertical-align: top; color: rgb(0, 0, 0);\">
                                 <span style=\"font-weight: bold; color: rgb(204, 0, 0);\">Total
                                 </span>
                                 <br>
                              </td>
                              <td style=\"vertical-align: top; text-align: right; color: rgb(0, 0, 0);\">
                                 <span style=\"font-weight: bold; color: rgb(204, 0, 0);\">%d
                                 </span>
                                 <br>
                              </td>
                           </tr>
                           <tr>
                              <td style=\"vertical-align: top; color: rgb(0, 0, 0);\">
                                 <span style=\"font-weight: bold; color: rgb(51, 51, 255);\">TCP
                                 </span>
                                 <br>
                              </td>
                              <td style=\"vertical-align: top; text-align: right; color: rgb(0, 0, 0);\">
                                 <span style=\"font-weight: bold; color: rgb(51, 51, 255);\">%d
                                 </span>
                                 <br>
                              </td>
                           </tr>
                           <tr>
                              <td style=\"vertical-align: top; color: rgb(0, 0, 0);\">
                                 <span style=\"font-weight: bold; color: rgb(0, 153, 0);\">UDP
                                 </span>
                                 <br>
                              </td>
                              <td style=\"vertical-align: top; text-align: right; color: rgb(0, 0, 0);\">
                                 <span style=\"font-weight: bold; color: rgb(0, 153, 0);\">%d
                                 </span>
                                 <br>
                              </td>
                           </tr>
                           <tr>
                              <td style=\"vertical-align: top;\">
                                 <span style=\"font-weight: bold;\">ICMP
                                 </span>
                                 <br>
                              </td>
                              <td style=\"vertical-align: top; text-align: right;\">
                                 <span style=\"font-weight: bold;\">%d
                                 </span>
                                 <br>
                              </td>
                           </tr>
                        </tbody>
                     </table>\n", $totalpkts, $tcppkts, $udppkts, $icmppkts
   );

   my @graph_src = ($tcppkts, $udppkts, $icmppkts);
   if ($graphics{'total'}->{'show'}) {
      &pie_total_graph("total", @graph_src);
   }

   # Honeypots' Caption

   open(HONEYPOT_CAPTION, ">" . $output_html_dir . "caption.html")
     || die("$program_name: cannot open file\n");
   printf(HONEYPOT_CAPTION
        "<\!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">
<html>
<head>
  <meta http-equiv=\"content-type\"
 content=\"text/html; charset=ISO-8859-15\">
  <title>Caption</title>\n"
   );

   printf(HONEYPOT_CAPTION "<script type=\"text/javascript\">
function AbreInst(theURL,winName,features) {
  window.open(theURL,winName,features);
}
</script>\n"
   );

   printf(HONEYPOT_CAPTION "  
</head>
<body>
<big><big style=\"font-weight: bold; color: rgb(204, 0, 0);\"></big></big>
<table cellpadding=\"2\" cellspacing=\"1\" border=\"1\" style=\"text-align: left; width: 210px; height: auto;\">
  <tbody>
    <tr>
      <td
 style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\"
 rowspan=\"1\" colspan=\"2\"> <big style=\"color: rgb(255, 255, 102);\"> <span style=\"font-weight: bold;\">HONEYPOT'S CAPTION </span> </big> <br style=\"color: rgb(0, 0, 0);\">
     
      </td>
    </tr>
    <tr>
        <td style=\"vertical-align: top; color: rgb(0, 0, 0); text-align: center; background-color: rgb(153, 153, 153);\">
      <span style=\"font-weight: bold; color: rgb(0, 0, 0);\">Honeypot</span><br>
      </td>
      <td style=\"vertical-align: top; color: rgb(0, 0, 0); text-align: center; background-color: rgb(153, 153, 153);\">
      <span style=\"font-weight: bold; color: rgb(0, 0, 0);\">IP</span><br>
     
      </td>
    </tr>\n"
   );

   # show graphics
   if ($graphics{'total'}->{'show'}) {
      printf(HTML_FILE "</td>
      <td style=\"text-align: center; vertical-align: middle;\"><img src=\"total.png\" title=\"%s\" alt=\"\" style=\"width: 282px; height: auto;\"></td>\n",
         $graphics{'total'}->{'title'}
      );
   }

   printf(HTML_FILE " </tr> </tbody> </table> <hr>\n");

   printf(HTML_FILE
"<table style=\"text-align: left; width: 717px; height: 369px;\" border=\"0\"
 cellspacing=\"3\" cellpadding=\"3\">
  <tbody>
    <tr>
      <td style=\"text-align: center; vertical-align: top;\">\n"
   );

   printf(HTML_FILE
"<table cellpadding=\"2\" cellspacing=\"1\" border=\"1\" style=\"text-align: left; width: 135px; height: auto;\">
                        <tbody>
                           <tr>
                              <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\" rowspan=\"1\" colspan=\"2\">
                                 <big style=\"color: rgb(255, 255, 102);\">
                                    <span style=\"font-weight: bold;\"><a name=\"honeypots\"></a>HONEYPOT'S</span>
                                 </big>
                                 <br>
                              </td>
                           </tr>\n"
   );

   my $counter = 1;
   $control = 0;
   foreach $nbr_dst_ip (sort { $a <=> $b } keys %stat_hash) {
      my %src_ip_hash = %{ $stat_hash{$nbr_dst_ip} };
      my $ip_flag;

      $dst_ip = join ".", unpack "C4", pack "N", $nbr_dst_ip;

      open(SRC_CAPTION, ">" . $output_html_dir . "caption_" . $dst_ip . ".html")
        || die("$program_name: cannot open file\n");
      printf(SRC_CAPTION
           "<\!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">
<html>
<head>
  <meta http-equiv=\"content-type\"
 content=\"text/html; charset=ISO-8859-15\">
  <title>Caption</title>
</head>
<body>
<big><big style=\"font-weight: bold; color: rgb(204, 0, 0);\"></big></big>
<table cellpadding=\"2\" cellspacing=\"1\" border=\"1\" style=\"text-align: left; width: 188px; height: auto;\">
  <tbody>
    <tr>
      <td
 style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\"
 rowspan=\"1\" colspan=\"2\"> <big style=\"color: rgb(255, 255, 102);\"> <span style=\"font-weight: bold;\">HONEYPOT'S CAPTION (%s)</span> </big> <br style=\"color: rgb(0, 0, 0);\">

      </td>
    </tr>
    <tr>
        <td style=\"vertical-align: top; color: rgb(0, 0, 0); text-align: center; background-color: rgb(192, 192, 192);\">
      <span style=\"font-weight: bold; color: rgb(0, 0, 0);\">Honeypot</span><br>
      </td>
      <td style=\"vertical-align: top; color: rgb(0, 0, 0); text-align: center; background-color: rgb(192, 192, 192);\">
      <span style=\"font-weight: bold; color: rgb(0, 0, 0);\">IP</span><br>
      </td>
    </tr>\n", $dst_ip
      );

      if ($control) {
         printf(HTML_FILE "<tr>
            <td style=\"background-color: rgb(192, 192, 192); font-weight: bold; text-align: left; vertical-align: middle;\">%d<br></td>
            <td class=\"square\" style=\"background-color: rgb(192, 192, 192); text-align: left; vertical-align: middle;\"> <a href=\"./%s.html\">%s </a> </td> </tr>\n",
            $counter, $dst_ip, $dst_ip
         );

         printf(HONEYPOT_CAPTION
"<tr> <td style=\"vertical-align: top; background-color: rgb(153, 153, 153);\"> <span style=\"font-weight: bold;\">%d</span><br></td> <td style=\"vertical-align: top; text-align: left; background-color: rgb(153, 153, 153);\">  <big style=\"font-weight: bold;\"><small><a href=\'#\' onClick=\"AbreInst(\'%s.html\',\'\',\'\')\">%s </a></small>  <span style=\"color: rgb(0, 153, 0);\"></span></big><br>       </td>     </tr>\n",
            $counter, $dst_ip, $dst_ip);

         $control = 0;
      } else {
         printf(HTML_FILE "<tr>
            <td style=\"font-weight: bold; text-align: left; vertical-align: middle;\">%d<br>
            </td>
            <td class=\"square\" style=\"text-align: left; vertical-align: middle;\">
            <a href=\"./%s.html\">%s </a> </td>
          </tr>\n", $counter, $dst_ip, $dst_ip
         );

         printf(HONEYPOT_CAPTION
"<tr> <td style=\"vertical-align: top; color: rgb(0, 0, 0);\"> <span style=\"font-weight: bold;\">%d</span><br> </td> <td style=\"vertical-align: top; color: rgb(0, 0, 0); text-align: left;\"> <big style=\"font-weight: bold;\"><small><a href=\'#\' onClick=\"AbreInst(\'%s.html\',\'\',\'\')\">%s </a></small> <span style=\"color: rgb(0, 153, 0);\"></span></big><br> </td> </tr>\n",
            $counter, $dst_ip, $dst_ip);

         $control = 1;
      }
      $counter++;

      # Honeypot IP page

      open(HONEYPOT_HTML, ">" . $output_html_dir . $dst_ip . ".html")
        || die("$program_name: cannot open file\n");

      printf(HONEYPOT_HTML
           "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\n");
      printf(HONEYPOT_HTML "\"http://www.w3.org/TR/html4/strict.dtd\">\n");
      printf(HONEYPOT_HTML "<html>\n");
      printf(HONEYPOT_HTML "<head>\n");
      printf(HONEYPOT_HTML "<script type=\"text/javascript\">
function AbreInst(theURL,winName,features) {
  window.open(theURL,winName,features);
}
</script>\n"
      );
      printf(HONEYPOT_HTML "<title>HONEYPOT: %s</title>\n", $dst_ip);
      printf(HONEYPOT_HTML
"<meta http-equiv=\"content-type\" content=\"text/html;charset=iso-8859-1\">\n"
      );
      printf(HONEYPOT_HTML "</head>\n");
      printf(HONEYPOT_HTML "<body>\n");
      ###################CONFIG######################
      #
      #
      if ($honeyd_conf) {
         my $per_tmp;
         if (defined($honeyd_conf_conv{$dst_ip})) {
            printf(HONEYPOT_HTML $honeyd_conf_print{'header'} . "\n");

            $per_tmp = $honeyd_conf_conv{$dst_ip};

            printf(HONEYPOT_HTML $honeyd_conf_print{$per_tmp} . "\n");
         } else {
            printf(HONEYPOT_HTML
"<table cellpadding=\"2\" cellspacing=\"1\" border=\"1\" style=\"text-align: left; width: 320px; height: auto;\">
  <tbody>
    <tr>
      <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\" rowspan=\"1\" colspan=\"1\"> <big style=\"color: rgb(255, 255, 102);\"> 
 <span style=\"font-weight: bold;\"><a name=\"honeypots_configuration\"></a>HONEYPOT'S CONFIGURATION<br>
      </span> </big> </td>
    </tr>
    <tr style=\"color: rgb(0, 0, 0);\">
      <td style=\"text-align: center; vertical-align: middle; background-color: rgb(192, 192, 192);\"
 rowspan=\"1\" colspan=\"1\"><big><span style=\"font-weight: bold;\">IP NOT CONFIGURED</span></big></td>
    </tr>\n"
            );
         }
         printf(HONEYPOT_HTML $honeyd_conf_print{'foot'} . "\n");

      }

      printf(HONEYPOT_HTML
"<table cellpadding=\"2\" cellspacing=\"1\" border=\"1\" style=\"text-align: left; width: 135px; height: auto;\"> <tbody> <tr> <td style=\"text-align: center; vertical-align: top;\">\n"
      );
      printf(HONEYPOT_HTML
"<table cellpadding=\"2\" cellspacing=\"1\" border=\"1\" style=\"text-align: left; width: 135px; height: 100px;\">
        <tbody>
          <tr>
            <td style=\"background-color: rgb(51, 51, 51); text-align: center; vertical-align: middle;\" rowspan=\"1\" colspan=\"4\"> 
            <big style=\"color: rgb(255, 255, 102);\"> 
            <span style=\"font-weight: bold;\">HONEYPOT: %s</span> </big> <br>
            </td>
          </tr>
          <tr>
            <td style=\"background-color: rgb(192, 192, 192); text-align: left; vertical-align: middle;\">
            <span style=\"font-weight: bold;\">Order</span><br>
            </td>
            <td class=\"square\" style=\"background-color: rgb(192, 192, 192);\">
            <span style=\"font-weight: bold;\">Source IP</span> </td>
                              <td class=\"square\" style=\"background-color: rgb(192, 192, 192);\">
                                 <span style=\"font-weight: bold;\">Resource</span>
                              </td>
                              <td class=\"square\" style=\"background-color: rgb(192, 192, 192); text-align: right;\">
                                 <span style=\"font-weight: bold;\">Connections</span>
                              </td>
                           </tr>\n", $dst_ip
      );

      %graph_hp_a = ();
      %graph_hp_b = ();
      $control_hp = 1;

      $total_ip          = 0;
      $total_connections = 0;
      @total_resource    = ();

      my $control_hp_caption  = 1;
      my $counter_src_caption = 1;
      foreach $nbr_src_ip (sort { $a <=> $b } keys %src_ip_hash) {
         $ip_flag = 0;

         my %proto_hash = %{ $src_ip_hash{$nbr_src_ip} };

         $src_ip = join ".", unpack "C4", pack "N", $nbr_src_ip;

         foreach $proto (keys %proto_hash) {
            my %resource_hash = %{ $proto_hash{$proto} };

            foreach $resource (sort { $a <=> $b } keys %resource_hash) {

               if ($ip_flag == 0) {
                  if ($control_hp_caption) {

                     printf(SRC_CAPTION
"<tr> <td style=\"vertical-align: top;\"> <span style=\"font-weight: bold;\">%d</span><br></td> <td style=\"vertical-align: top; text-align: left;\">  <big style=\"font-weight: bold;\"><small>%s </small>  <span style=\"color: rgb(0, 153, 0);\"></span></big><br></td></tr>\n",
                        $counter_src_caption, $src_ip);

                     $control_hp_caption = 0;
                  } else {

                     printf(SRC_CAPTION
"<tr> <td style=\"vertical-align: top; background-color: rgb(192, 192, 192);\"> <span style=\"font-weight: bold;\">%d</span><br></td> <td style=\"vertical-align: top; text-align: left; background-color: rgb(192, 192, 192);\">  <big style=\"font-weight: bold;\"><small>%s </small>  <span style=\"color: rgb(0, 153, 0);\"></span></big><br>       </td>     </tr>\n",
                        $counter_src_caption, $src_ip);

                     $control_hp_caption = 1;
                  }

                  $counter_src_caption++;
               }

               printf(HONEYPOT_HTML "<tr>\n");
               $total_connections =
                 $total_connections + $resource_hash{$resource};
               push(@total_resource, $resource);

               if (!exists $graph_hp_a{$resource}) {
                  $graph_hp_a{$resource} = $resource_hash{$resource};
               } else {
                  $graph_hp_a{$resource} = $graph_hp_a{$resource} + $resource_hash{$resource};
               }

               if (!exists $graph_hp_b{$nbr_src_ip}) {

                  $graph_hp_b{$nbr_src_ip} = { $resource => $resource_hash{$resource} };


               } else {

                  if (!exists $graph_hp_b{$nbr_src_ip}->{$resource}) {
                     $graph_hp_b{$nbr_src_ip}->{$resource} = $resource_hash{$resource};
                  } else {
                     $graph_hp_b{$nbr_src_ip}->{$resource} =
                       ($graph_hp_b{$nbr_src_ip}->{$resource} +
                          $resource_hash{$resource});
                  }
               }

               if ($ip_flag == 0) {
                  if ($control_hp) {
                     printf(HONEYPOT_HTML
"<td>%d</td><td>%s</td><td align=right>%s/%s</td><td align=right>%d</td>\n",
                        ($counter_src_caption - 1),
                        $src_ip, $resource, $proto, $resource_hash{$resource}
                     );

                     $control_hp = 0;
                  } else {
                     printf(HONEYPOT_HTML
"<td style=\"background-color: rgb(192, 192, 192);\">%d</td><td style=\"background-color: rgb(192, 192, 192);\">%s</td><td align=\"right\" style=\"background-color: rgb(192, 192, 192);\">%s/%s</td><td align=\"right\" style=\"background-color: rgb(192, 192, 192);\">%d</td>\n",
                        ($counter_src_caption - 1),
                        $src_ip, $resource, $proto, $resource_hash{$resource}
                     );

                     $control_hp = 1;
                  }
                  $total_ip++;
                  $ip_flag = 1;
               } else {
                  if ($control_hp) {
                     printf(HONEYPOT_HTML
"<td>-</td><td></td><td align=right>%s/%s</td><td align=right>%d</td>\n",
                        $resource, $proto, $resource_hash{$resource});

                     $control_hp = 0;
                  } else {
                     printf(HONEYPOT_HTML
"<td style=\"background-color: rgb(192, 192, 192);\">-</td><td style=\"background-color: rgb(192, 192, 192);\"></td><td align=\"right\" style=\"background-color: rgb(192, 192, 192);\">%s/%s</td><td align=\"right\" style=\"background-color: rgb(192, 192, 192);\">%d</td>\n",
                        $resource, $proto, $resource_hash{$resource});

                     $control_hp = 1;
                  }
               }
               printf(HONEYPOT_HTML "</tr>\n");

            }
         }
      }

      # creating hp graphics
      if ($graphics{'ip_b'}->{'show'}) {
         &hp_source_ip_graph($dst_ip, \%graph_hp_b);
      }

      # creating hp graphics
      if ($graphics{'ip_a'}->{'show'}) {
         &hp_resources_graph($dst_ip, \%graph_hp_a);
      }

      my (%seen) = ();
      my ($item) = ();
      foreach $item (@total_resource) {
         $total_resource_number++ unless $seen{$item}++;
      }

      printf(HONEYPOT_HTML "<tr>\n");
      printf(HONEYPOT_HTML
"<td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\">
                              </td>
<td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\">
                                 <big style=\"color: rgb(255, 255, 102);\">
                                    <span style=\"font-weight: bold;\">IPs</span>
                                 </big>
                                 <br>
                              </td>
                              <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\">
                                 <big style=\"color: rgb(255, 255, 102);\">
                                    <span style=\"font-weight: bold;\">Resources</span>
                                 </big>
                                 <br>
                              </td>
                              <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\">
                                 <big style=\"color: rgb(255, 255, 102);\">
                                    <span style=\"font-weight: bold;\">Connections</span>
                                 </big>
                                 <br>
                              </td>
                                 </tr>\n"
      );

      printf(HONEYPOT_HTML
"<tr><td align=\"center\" style=\"background-color: rgb(192, 192, 192);\"></td>"
      );

      printf(HONEYPOT_HTML
"<td align=\"center\" style=\"background-color: rgb(192, 192, 192);\"><span style=\"font-weight: bold;\">%d</span></td>",
         $total_ip
      );
      printf(HONEYPOT_HTML
"<td align=\"center\" style=\"background-color: rgb(192, 192, 192);\"><span style=\"font-weight: bold;\">%d</span></td>",
         $total_resource_number
      );
      printf(HONEYPOT_HTML
"<td align=\"center\" style=\"background-color: rgb(192, 192, 192);\"><span style=\"font-weight: bold;\">%d</span></td>",
         $total_connections
      );
      printf(HONEYPOT_HTML "</tr>\n");

      push(@ip_high,   $dst_ip);
      push(@total_res, $total_resource_number);
      push(@total_ips, $total_ip);
      push(@total_con, $total_connections);

      $total_resource_number = 0;
      $total_ip              = 0;
      $total_connections     = 0;

      printf(HONEYPOT_HTML "</tbody>\n");
      printf(HONEYPOT_HTML "</table>\n");

      if ($graphics{'ip_a'}->{'show'} && $graphics{'ip_b'}->{'show'}) {
         printf(HONEYPOT_HTML "</td>
            <td style=\"text-align: center; vertical-align: top;\"><img src=\"%s_a.png\" title=\"%s\" alt=\"\" style=\"width: 400px; height: 350px;\"><br>\n",
            $dst_ip, $graphics{'ip_a'}->{'title'}
         );
         printf(HONEYPOT_HTML
"<br><hr><img src=\"%s_b.png\" title=\"%s\" alt=\"\" style=\"width: 480px; height: 300px;\">\n",
            $dst_ip, $graphics{'ip_b'}->{'title'});
         printf(HONEYPOT_HTML "<a href=\'#\' onClick=\"AbreInst(\'caption_"
              . $dst_ip
              . ".html\',\'\',\'location=no, toolbar=no,directories=no,menubar=no,resizable=no,status=no,scrollbars=yes,width=250,height=800\')\">CAPTION</a><br>\n"
         );
      } elsif ($graphics{'ip_a'}->{'show'} && !$graphics{'ip_b'}->{'show'}) {
         printf(HONEYPOT_HTML "</td>
            <td style=\"text-align: center; vertical-align: top;\"><img src=\"%s_a.png\" title=\"%s\" alt=\"\" style=\"width: 400px; height: 350px;\"><br><br>\n",
            $dst_ip, $graphics{'ip_a'}->{'title'}
         );
      } elsif (!$graphics{'ip_a'}->{'show'} && $graphics{'ip_b'}->{'show'}) {
         printf(HONEYPOT_HTML "</td>
            <td style=\"text-align: center; vertical-align: top;\"><img src=\"%s_b.png\" title=\"%s\" alt=\"\" style=\"width: 450px; height: 300px;\"><br>\n",
            $dst_ip, $graphics{'ip_b'}->{'title'}
         );
         printf(HONEYPOT_HTML "<a href=\'#\' onClick=\"AbreInst(\'caption_"
              . $dst_ip
              . ".html\',\'\',\'location=no, toolbar=no,directories=no,menubar=no,resizable=no,status=no,scrollbars=yes,width=250,height=800\')\">CAPTION</a><br>\n"
         );
      }

      printf(HONEYPOT_HTML "</td></tr></tbody></table></body></html>\n");

      close(HONEYPOT_HTML);
      printf(SRC_CAPTION "</tbody> </table> <br> 
                                      <a href=\"#\" onClick=\"window.close(-1)\"><small>close</small>
                                </a>
    </body> </html>\n"
      );
      close(SRC_CAPTION);

   }

   printf(HONEYPOT_CAPTION "</tbody> </table> <br> 
                                      <a href=\"#\" onClick=\"window.close(-1)\"><small>close</small>
                                </a>
    </body> </html>\n"
   );
   close(HONEYPOT_CAPTION);

   printf(HTML_FILE "   </tbody>
                     </table></td>\n"
   );

   # show graphics
   if ($graphics{'honeypot_connections'}->{'show'}) {
      printf(HTML_FILE "
      <td style=\"text-align: center; vertical-align: middle;\"> <span
 style=\"font-weight: bold;\"><img src=\"honeypot_connections.png\"
 title=\"%s\" alt=\"\" style=\"width: 539px; height: 310px;\"></span><br>
      </td>\n", $graphics{'honeypot_connections'}->{'title'}
      );
   }

   printf(HTML_FILE " </tr> </tbody> </table> <hr>\n");

   # show graphics
   if ($graphics{'top_src'}->{'show'} || $graphics{'honeypot_ips'}->{'show'}) {
      printf(HTML_FILE
"<table style=\"text-align: left; height: 321px; width: 737px;\" border=\"0\" cellspacing=\"3\" cellpadding=\"3\"> <tbody> <tr> <td style=\"text-align: center; vertical-align: middle;\">\n"
      );
   }

   printf(HTML_FILE
"<table cellpadding=\"2\" cellspacing=\"1\" border=\"1\" style=\"text-align: left; width: 268px; height: auto;\">
                        <tbody>
                           <tr>
                              <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\" rowspan=\"1\" colspan=\"3\"><big style=\"color: rgb(255, 255, 102);\"><span style=\"font-weight: bold;\"><a name=\"top_source\"></a>Top %s Source Hosts</span></big></td>
                           </tr>
                           <tr>
                              <td class=\"square\" style=\"background-color: rgb(192, 192, 192);\"><span style=\"font-weight: bold;\">Rank</span>
			      </td>
                              <td class=\"square\" style=\"background-color: rgb(192, 192, 192);\">
                                 <span style=\"font-weight: bold;\">Source IP</span>
                              </td>
                              <td class=\"square\" style=\"background-color: rgb(192, 192, 192); text-align: right;\">
                                 <span style=\"font-weight: bold;\">Connections</span>
                              </td>
                           </tr>\n", ($top_show - 1)
   );

   @graph_src = ();
   $cnt       = 1;
   $control   = 1;
   foreach $src_ip (
      sort { $src_host_hash{$b} <=> $src_host_hash{$a} }
      keys %src_host_hash
     )
   {
      printf(HTML_FILE "<tr>\n");
      if ($control) {
         printf(HTML_FILE
"<td style=\"font-weight: bold; text-align: left; vertical-align: middle;\">%d</td><td>%s</td><td align=\"right\">%d</td>",
            $cnt, $src_ip, $src_host_hash{$src_ip});

         $control = 0;
      } else {
         printf(HTML_FILE
"<td style=\"font-weight: bold; text-align: left; vertical-align: middle; background-color: rgb(192, 192, 192);\">%d</td><td style=\"background-color: rgb(192, 192, 192);\">%s</td><td align=\"right\" style=\"background-color: rgb(192, 192, 192);\">%d</td>\n",
            $cnt, $src_ip, $src_host_hash{$src_ip});

         $control = 1;
      }
      printf(HTML_FILE "</tr>\n");
      push(@graph_src, $src_host_hash{$src_ip});
      $cnt++;
      if ($cnt == $top_show) {
         last;
      }
   }

   printf(HTML_FILE "</tbody> </table> \n");

   # show graphics
   if ($graphics{'top_src'}->{'show'}) {
      printf(HTML_FILE "</td>\n");
      &bar_graph("top_src", @graph_src);

      printf(HTML_FILE
"<td style=\"vertical-align: middle; text-align: center;\"><img src=\"top_src.png\" title=\"%s\" alt=\"\" style=\"width: 500px; height: 300px;\"></td> </tr>\n",
         $graphics{'top_src'}->{'title'}
      );
   }

   # show graphics
   if ($graphics{'honeypot_ips'}->{'show'}) {
      printf(HTML_FILE "<tr>
      <td style=\"vertical-align: middle; text-align: center;\" rowspan=\"1\" colspan=\"2\"> 
      <span style=\"font-weight: bold;\"><a name=\"top_source_img\"></a>
      <img src=\"honeypot_ips.png\" title=\"%s\" alt=\"\" style=\"height: 300px; width: 613px;\">
      </span><br>
      <div style=\"text-align: right;\"><small>
      <a href=\"#top_source_img\" onclick=\"AbreInst('caption.html','','location=no, toolbar=no,directories=no,menubar=no,resizable=no,status=no,scrollbars=yes,width=250,height=500')\">HONEYPOT'S CAPTION</a></small><br>
      </div>
      </td></tr>\n", $graphics{'honeypot_ips'}->{'title'}
      );

   }

   # show graphics
   if ($graphics{'top_src'}->{'show'} || $graphics{'honeypot_ips'}->{'show'}) {
      printf(HTML_FILE "</tbody> </table>\n");
   }

   printf(HTML_FILE "<hr>\n");

   # show graphics
   if (  $graphics{'top_port'}->{'show'}
      || $graphics{'honeypot_resources'}->{'show'})
   {
      printf(HTML_FILE
"<table style=\"text-align: left; height: 268px; width: 737px;\" border=\"0\" cellspacing=\"3\" cellpadding=\"3\"> <tbody> <tr> <td style=\"text-align: center; vertical-align: middle;\">\n"
      );
   }
   printf(HTML_FILE
"<table cellpadding=\"2\" cellspacing=\"1\" border=\"1\" style=\"text-align: left; height: auto; width: 266px;\">
			   <tbody>
			      <tr>
			         <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\" rowspan=\"1\" colspan=\"3\">
				    <big style=\"color: rgb(255, 255, 102);\">
				       <span style=\"font-weight: bold;\"><a name=\"top_accessed\"></a>Top %s Accessed Resources</span>
				    </big>
				 </td>
    			      </tr>
    			      <tr>
      			         <td style=\"background-color: rgb(192, 192, 192);\">
			            <b>Rank
				    </b>
				 </td>
      				 <td style=\"background-color: rgb(192, 192, 192);\">
				    <b>Resource
				    </b>
				 </td>
      				 <td style=\"background-color: rgb(192, 192, 192); text-align: right;\">
				    <b>Connections
				    </b>
				 </td>
    		              </tr>\n", ($top_show - 1)
   );

   $cnt       = 1;
   $control   = 1;
   @graph_src = ();
   foreach $port (
      sort { $resource_hash{$b} <=> $resource_hash{$a} }
      keys %resource_hash
     )
   {
      printf(HTML_FILE "<tr>\n");
      if ($control) {

         printf(HTML_FILE
"<td style=\"font-weight: bold; text-align: left; vertical-align: middle;\">%d</td><td align=\"right\">%s</td><td align=\"right\">%d</td>",
            $cnt, $port, $resource_hash{$port});
         $control = 0;
      } else {
         printf(HTML_FILE
"<td style=\"font-weight: bold; text-align: left; vertical-align: middle; background-color: rgb(192, 192, 192);\">%d</td><td align=\"right\" style=\"background-color: rgb(192, 192, 192);\">%s</td><td align=\"right\" style=\"background-color: rgb(192, 192, 192);\">%d</td>",
            $cnt, $port, $resource_hash{$port});
         $control = 1;
      }
      printf(HTML_FILE "</tr>\n");
      push(@graph_src, $resource_hash{$port});
      $cnt++;
      if ($cnt == $top_show) {
         last;
      }
   }

   printf(HTML_FILE "</tbody> </table>\n");

   # show graphics
   if ($graphics{'top_port'}->{'show'}) {
      &bar_graph("top_port", @graph_src);

      printf(HTML_FILE
"<td style=\"vertical-align: middle; text-align: center;\"><img src=\"top_port.png\" title=\"%s\" alt=\"\" style=\"width: 500px; height: 300px;\"></td> </tr>\n",
         $graphics{'top_port'}->{'title'}
      );
   }

   # show graphics
   if ($graphics{'honeypot_resources'}->{'show'}) {
      printf(HTML_FILE "<tr>
      <td style=\"text-align: center; vertical-align: middle;\" rowspan=\"1\" colspan=\"2\">
      <span style=\"font-weight: bold;\"><a name=\"top_accessed_img\"></a>
      <img src=\"honeypot_resources.png\" title=\"%s\" alt=\"\" style=\"height: 300px; width: 650px;\"><br>
      </span>
      <div style=\"text-align: right;\"><small><a href=\"#top_accessed_img\" onclick=\"AbreInst('caption.html','','location=no, toolbar=no,directories=no,menubar=no,resizable=no,status=no,scrollbars=yes,width=250,height=500')\">HONEYPOT'S CAPTION</a><br>
      </small></div>
      </td></tr>\n", $graphics{'honeypot_resources'}->{'title'}
      );
   }

   # show graphics
   if (  $graphics{'top_port'}->{'show'}
      || $graphics{'honeypot_resources'}->{'show'})
   {
      printf(HTML_FILE " </tbody> </table>");
   }

   if ($proto_show == 0 || $proto_show == 5 || $proto_show == 6) {
      printf(HTML_FILE "<hr>\n");
      if ($graphics{'top_icmp'}->{'show'}) {

         printf(HTML_FILE
"<table style=\"text-align: left; height: 321px; width: 737px;\" border=\"0\" cellspacing=\"3\" cellpadding=\"3\"> <tbody> <tr> <td style=\"text-align: center; vertical-align: middle;\">\n"
         );
      }

      printf(HTML_FILE
"<table cellpadding=\"2\" cellspacing=\"1\" border=\"1\" style=\"text-align: left; width: 266px; height: auto;\">
  		        <tbody>
    				<tr>
      					<td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51);\" rowspan=\"1\" colspan=\"3\">
						<big style=\"color: rgb(255, 255, 102);\">
						<span style=\"font-weight: bold;\"><a name=\"top_icmp\"></a>Top %s ICMP &gt; 40 bytes Senders</span>
						</big>
      					</td>
    				</tr>
    				<tr>
      					<td style=\"background-color: rgb(192, 192, 192);\">
						<b>Rank
						</b>
					</td>
      					<td style=\"background-color: rgb(192, 192, 192);\">
						<b>Source IP
						</b>
					</td>
      					<td style=\"background-color: rgb(192, 192, 192); text-align: right;\">
						<b>Connections
						</b>
					</td>
    				</tr>\n", ($top_show - 1)
      );

      $cnt       = 1;
      $control   = 1;
      @graph_src = ();
      foreach $src_ip (
         sort { $icmp_b40_hash{$b} <=> $icmp_b40_hash{$a} }
         keys %icmp_b40_hash
        )
      {
         printf(HTML_FILE "<tr>\n");
         if ($control) {
            printf(HTML_FILE
"<td style=\"font-weight: bold; text-align: left; vertical-align: middle;\">%d</td><td>%s</td><td align=right>%d</td>",
               $cnt, $src_ip, $icmp_b40_hash{$src_ip});
            $control = 0;
         } else {
            printf(HTML_FILE
"<td style=\"font-weight: bold; text-align: left; vertical-align: middle; background-color: rgb(192, 192, 192);\">%d</td><td style=\"background-color: rgb(192, 192, 192);\">%s</td><td align=\"right\" style=\"background-color: rgb(192, 192, 192);\">%d</td>",
               $cnt, $src_ip, $icmp_b40_hash{$src_ip});
            $control = 1;
         }
         printf(HTML_FILE "</tr>\n");
         push(@graph_src, $icmp_b40_hash{$src_ip});
         $cnt++;
         if ($cnt == $top_show) {
            last;
         }
      }

      printf(HTML_FILE "</tbody> </table> \n");
      
      # show graphics
      if ($graphics{'top_icmp'}->{'show'}) {
         &bar_graph("top_icmp", @graph_src);
         printf(HTML_FILE "</td>
      <td style=\"vertical-align: middle; text-align: center;\"><img src=\"top_icmp.png\" title=\"%s\" alt=\"\" style=\"width: 500px; height: 300px;\"></td>
    </tr>
  </tbody>
</table>\n", $graphics{'top_icmp'}->{'title'}
         );
      }
   }
   printf(HTML_FILE "<hr>\n");
   
   # show graphics
   if ($graphics{'hour'}->{'show'}) {
      printf(HTML_FILE
"<table style=\"text-align: left; height: 321px; width: 737px;\" border=\"0\" cellspacing=\"3\" cellpadding=\"3\">
  <tbody>
    <tr>
      <td style=\"text-align: center; vertical-align: middle;\">\n"
      );
   }

   printf(HTML_FILE
"<table cellpadding=\"2\" cellspacing=\"1\" border=\"1\" style=\"text-align: left; height: auto; width: 156px;\">
  <tbody>
    <tr>
      <td style=\"vertical-align: top; text-align: center; background-color: rgb(51, 51, 51); white-space: nowrap;\"
 rowspan=\"1\" colspan=\"2\"><big style=\"color: rgb(255, 255, 102);\"><span style=\"font-weight: bold;\"><a name=\"connections\"></a>Connections per Hour</span></big> </td>
    </tr>
    <tr>
      <td style=\"background-color: rgb(192, 192, 192);\"><b>Hour</b></td>
      <td style=\"text-align: right; background-color: rgb(192, 192, 192);\"><b>Connections</b></td>
    </tr>\n"
   );

   $control   = 1;
   @graph_src = ();
   foreach $hour (sort { $a cmp $b } keys %hour_hash) {
      printf(HTML_FILE "<tr>\n");
      if ($control) {
         printf(HTML_FILE "<td>%s:00</td><td align=\"right\">%d</td>\n",
            $hour, $hour_hash{$hour});
         $control = 0;
      } else {
         printf(HTML_FILE
"<td style=\"background-color: rgb(192, 192, 192);\">%s:00</td><td align=\"right\" style=\"background-color: rgb(192, 192, 192);\">%d</td>\n",
            $hour, $hour_hash{$hour});
         $control = 1;
      }
      printf(HTML_FILE "</tr>\n");
      push(@graph_src, $hour_hash{$hour});
   }

   printf(HTML_FILE "</tbody> </table> \n");

   # show graphics
   if ($graphics{'hour'}->{'show'}) {
      &bar_graph("hour", @graph_src);

      printf(HTML_FILE "</td>
      <td style=\"vertical-align: middle; text-align: center;\"><img src=\"hour.png\" title=\"%s\" alt=\"\" style=\"width: 595px; height: 360px;\"></td>
    </tr>
  </tbody>
</table>\n", $graphics{'hour'}->{'title'}
      );
   }
   printf(HTML_FILE "<hr>\n");

   printf(HTML_FILE "</body>\n");
   printf(HTML_FILE "</html>");
}

if (defined($option{'w'})) {
   close(HTML_FILE);
   if ($graphics{'honeypot_connections'}->{'show'}) {
      &main_graph("honeypot_connections");
   }
   if ($graphics{'honeypot_ips'}->{'show'}) {
      &main_graph("honeypot_ips");
   }
   if ($graphics{'honeypot_resources'}->{'show'}) {
      &main_graph("honeypot_resources");
   }
}

exit 0;

# end of main

##########################################################################
### Subroutines

#-------------------------------------------------------------------------
# Name: ext_honeyd_conf
#
# Description: Extracts the configuration of honeyd
#
# Return values:
#    none
#

sub ext_honeyd_conf {
   my ($file, $viewer, $line);
   my ($pid);
   my ($control);
   my ($create_flag)=1;
   my ($personality);
   my ($system_aux) = ();
   my (@tcp_ports)  = ();
   my (@udp_ports)  = ();
   my (@ips)        = ();
   my (@ips_aux)    = ();

   my ($tcp_action)  = "-";
   my ($udp_action)  = "-";
   my ($icmp_action) = "-";
   my $control_conf  = 0;

   if (!($file = &check_filename($_[0]))) {
      $file = quotemeta($_[0]);
      warn("$program_name: $file: invalid file name.\n");
      next;
   }

   if ($file =~ /\.bz2$/) {
      $viewer = $bzcat;
   } elsif ($file =~ /\.gz$/) {
      $viewer = $zcat;
   } else {
      $viewer = $cat;
   }

   my @viewer_args = ();
   push(@viewer_args, $file);

   if (!defined($option{'w'})) {
      printf("\n### Honeypot's Configuration ###\n");
   } else {
      printf(HTML_FILE $honeyd_conf_print{'header'} . "\n");
   }

   $pid = open(CHILD_TO_READ3, "-|");

   if (!$pid) {

      # child
      exec($viewer, @viewer_args)
        || die("$program_name: $viewer: cannot exec: $!\n");

      # never reached
   } else {

      # parent
      $create_flag = 1;

      while ($line = <CHILD_TO_READ3>) {
         if ($create_flag < 0) {

            if ($#IP_list != -1) {
               $control = 0;
               if ($#ips != -1) {
                  foreach my $ip (@ips) {
                     if (&check_list($ip, @IP_list) == 1) {
                        $control = 1;
                        push(@ips_aux, $ip);
                     }
                  }
               }
            } else {
               $control = 1;
            }

            if ($control == 1) {    #it found the ip
               if (!defined($option{'w'})) {
                  printf("\n");
                  printf($personality);
                  printf("\n");
               } else {
                  $personality = $personality . "###";
                  my $per;
                  if (!defined($honeyd_conf_print{$personality})) {
                     $per = $personality;
                     $per =~ s/###$//g;
                     $honeyd_conf_print{$personality} = (
"<tr> <td style=\"text-align: center; background-color: rgb(192, 192, 192);\"> <b>$per </b> </td> <td style=\"text-align: center; background-color: rgb(192, 192, 192);\"> <b>$tcp_action </b> </td> <td style=\"text-align: center; background-color: rgb(192, 192, 192);\"> <b>$udp_action </b> </td> <td style=\"text-align: center; background-color: rgb(192, 192, 192);\"> <b>$icmp_action </b> </td>"
                     );
                  } else {
                     $personality = $personality . $person;
                     $per         = $personality;
                     $per =~ s/###\w*$//g;
                     $honeyd_conf_print{$personality} = (
"<tr> <td style=\"text-align: center; background-color: rgb(192, 192, 192);\"> <b>$per </b> </td> <td style=\"text-align: center; background-color: rgb(192, 192, 192);\"> <b>$tcp_action </b> </td> <td style=\"text-align: center; background-color: rgb(192, 192, 192);\"> <b>$udp_action </b> </td> <td style=\"text-align: center; background-color: rgb(192, 192, 192);\"> <b>$icmp_action </b> </td>"
                     );
                     $person++;
                  }
                  printf(HTML_FILE $honeyd_conf_print{$personality} . "\n");
               }

               if ($#IP_list != -1) {
                  @ips = @ips_aux;
               }

               if ($#ips != -1) {
                  if (!defined($option{'w'})) {
                     printf("\t( / ");
                     foreach my $ip (@ips) {
                        printf("%s / ", $ip);

                     }
                     printf(")\n");
                  }
               }

               if (defined($option{'w'})) {
                  $honeyd_conf_print{$personality} =
                    ($honeyd_conf_print{$personality}
                       . "<td style=\"text-align: right; background-color: rgb(192, 192, 192);\">"
                    );
                  printf(HTML_FILE "
                    	   <td style=\"text-align: right; background-color: rgb(192, 192, 192);\">\n"
                  );
               }
               if ($#tcp_ports != -1) {
                  foreach my $port (@tcp_ports) {
                     if (!defined($option{'w'})) {
                        printf("\t%s/tcp\n", $port);
                     } else {
                        $honeyd_conf_print{$personality} =
                          ($honeyd_conf_print{$personality}
                             . "<b>$port/tcp</b><br>");
                        printf(HTML_FILE "
                              <b>%s/tcp
                              </b>\n", $port
                        );
                     }
                  }
               } else {
                  if (defined($option{'w'}) && $#udp_ports == -1) {
                     $control_conf = 1;
                  }
               }

               if ($#udp_ports != -1) {
                  foreach my $port (@udp_ports) {
                     if (!defined($option{'w'})) {
                        printf("\t%s/udp\n", $port);
                     } else {
                        $honeyd_conf_print{$personality} =
                          ($honeyd_conf_print{$personality}
                             . "<b>$port/udp</b><br>");
                        printf(HTML_FILE "
                              <b>%s/udp
                              </b>\n", $port
                        );
                     }
                  }

               } else {
                  if (defined($option{'w'}) && $control_conf) {
                     $honeyd_conf_print{$personality} =
                       ($honeyd_conf_print{$personality} . "-</td>");
                     printf(HTML_FILE "-</td>\n");
                     $control_conf = 0;
                  }
               }

               if ($#ips != -1) {
                  if (defined($option{'w'})) {

                     $honeyd_conf_print{$personality} =
                       ($honeyd_conf_print{$personality}
                          . "<td style=\"text-align: left; background-color: rgb(192, 192, 192);\"><big>"
                       );
                     printf(HTML_FILE "
                        <td style=\"text-align: left; background-color: rgb(192, 192, 192);\">
						      <big>\n"
                     );
                     foreach my $ip (@ips) {
                        $honeyd_conf_print{$personality} =
                          ($honeyd_conf_print{$personality}
                             . "<a href=\"./$ip.html\">$ip</a><br>");
                        printf(HTML_FILE "<a href=\"./%s.html\">%s</a><br>\n",
                           $ip, $ip);

                        $honeyd_conf_conv{$ip} = ($personality);
                     }
                     $honeyd_conf_print{$personality} =
                       ($honeyd_conf_print{$personality} . "</big></td>");
                     printf(HTML_FILE "</big></td>\n");
                  }
               } else {
                  if (defined($option{'w'})) {
                     $honeyd_conf_print{$personality} =
                       ($honeyd_conf_print{$personality}
                          . "<td style=\"text-align: left; background-color: rgb(192, 192, 192);\">-</td>"
                       );
                     printf(HTML_FILE
"<td style=\"text-align: left; background-color: rgb(192, 192, 192);\">-</td>\n"
                     );
                  }
               }
               if (defined($option{'w'})) {
                  $honeyd_conf_print{$personality} =
                    ($honeyd_conf_print{$personality} . "</tr>");
                  printf(HTML_FILE "</tr>");
               }

            }
            @tcp_ports = ();
            @udp_ports = ();
            @ips       = ();
            @ips_aux   = ();

            ($tcp_action)  = "-";
            ($udp_action)  = "-";
            ($icmp_action) = "-";

            $create_flag++;
         }

         if ($line =~ /^create\s+(.*)/) {
            $create_flag--;
            $system_aux = $1;
         } elsif ($line =~ /^set\s+\w+\s+personality\s+\"(.*)\"/) {
            $personality = $1;
         } elsif ($line =~ /^add\s+\w+\s+tcp\s+port\s+(\d{1,5})\s+.*/) {
            push(@tcp_ports, $1);
         } elsif ($line =~ /^add\s+\w+\s+udp\s+port\s+(\d{1,5})\s+.*/) {
            push(@udp_ports, $1);
         } elsif ($line =~ /^bind\s+($IP_exp)\s+(.*)/) {
            if ($#real_hp_net != -1) {
               if (&check_ip($1)) {
                  push(@ips, &sanitize_ip($1, \@real_hp_net, \@fake_hp_net));
               } else {
                  close(CHILD_TO_READ3);
                  if (defined($option{'w'})) {
                     close(HTML_FILE);
                  }
                  exit 1;
               }
            } else {
               push(@ips, $1);
            }
         }

         elsif ($line =~ /^set\s+\w+\s+default\s+tcp\s+action\s+(\w+)/) {
            $tcp_action = $1;
         } elsif ($line =~ /^set\s+\w+\s+default\s+udp\s+action\s+(\w+)/) {
            $udp_action = $1;
         } elsif ($line =~ /^set\s+\w+\s+default\s+icmp\s+action\s+(\w+)/) {
            $icmp_action = $1;
         }
      }#while
   }

   close(CHILD_TO_READ3) || warn("$program_name: $viewer: exited $?\n");

   if (defined($option{'w'})) {
      printf(HTML_FILE $honeyd_conf_print{'foot'} . "\n");
   }
}

#-------------------------------------------------------------------------
# Name: check_ip
#
# Description: checks if the IP passed to it is a valid IP address.
#
# Return values:
#   1 = success
#   0 = fail
#

sub check_ip {
   my ($IP) = @_;
   my ($oct1, $oct2, $oct3, $oct4);

   if ($IP =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/) {
      $oct1 = $1;
      $oct2 = $2;
      $oct3 = $3;
      $oct4 = $4;

      if (  (($oct1 >= 0) && ($oct1 <= 255))
         && (($oct2 >= 0) && ($oct2 <= 255))
         && (($oct3 >= 0) && ($oct3 <= 255))
         && (($oct4 >= 0) && ($oct4 <= 255)))
      {
         return 1;
      } else {
         warn("$program_name: " . $IP . " invalid IP address.\n");
         return 0;
      }
   } else {
      $IP = quotemeta($IP);
      warn("$program_name: " . $IP . " this isn't an IP address.\n");
      return 0;
   }
}

#-------------------------------------------------------------------------
# Name: check_port
#
# Description: checks if the PORT passed to it is valid.
#
# Return values:
#   1 = success
#   0 = fail
#

sub check_port {
   my ($PORT) = @_;
   my ($port1);

   if ($PORT =~ /(\d{1,5})/) {
      $port1 = $1;

      if ((($port1 >= 0) && ($port1 <= 65535))) {
         return 1;
      } else {
         warn("$program_name: " . $PORT . " invalid port number.\n");
         return 0;
      }
   } else {
      $PORT = quotemeta($PORT);
      warn("$program_name: " . $PORT . " this isn't a port number.\n");
      return 0;
   }
}

#-------------------------------------------------------------------------
# Name: check_proto
#
# Description: checks if the PROTOCOL passed to it is valid.
#
# Return values:
#   1 = success
#   0 = fail
#

sub check_proto {
   my ($PROTO) = @_;

   if ($PROTO =~ /tcp/) {
      $proto_show += 1;
      return 1;
   } elsif ($PROTO =~ /udp/) {
      $proto_show += 2;
      return 1;
   } elsif ($PROTO =~ /icmp/) {
      $proto_show += 4;
      return 1;
   } else {
      warn("$program_name: " . $PROTO . " invalid protocol name.\n");
      return 0;
   }
}

#-------------------------------------------------------------------------
# Name: set_list
#
# Description: retrieves the arguments passed to the fuction and
#              return a new list
#

sub set_list {
   my ($check_option) = $_[0];
   shift @_;
   my ($LISTs)      = @_;
   my (@local_list) = ();
   my @aux_list;

   @aux_list = split(/\s*\,\s*/, $LISTs);

   if ($#aux_list != -1) {
      foreach my $list (@aux_list) {
         if ($check_option =~ /IP/) {
            if (&check_ip($list)) {
               push(@local_list, $list);
            }
         } elsif ($check_option =~ /NET/) {
            if (&check_ip($list)) {
               push(@local_list, $list);
            }
         } elsif ($check_option =~ /PORT/) {
            if (&check_port($list)) {
               push(@local_list, $list);
            }
         } elsif ($check_option =~ /PROTO/) {
            if (&check_proto($list)) {
               push(@local_list, $list);
            }
         }
      }
   }
   return @local_list;
}

#-------------------------------------------------------------------------
# Name: check_list
#
# Description: checks if the argument passed to the function belongs to
#              (@*_list)
#
# Return values:
#   1 = success
#   0 = fail
#

sub check_list {
   my ($ELEMENT) = $_[0];
   shift @_;
   my (@LIST) = @_;

   foreach my $list_elem (@LIST) {
      if ("$ELEMENT" eq "$list_elem") {
         return 1;
      }
   }
   return 0;
}

#-------------------------------------------------------------------------
# Name: check_net_list
#
# Description: checks if the IP passed to the function belongs to
#              (@NET_list)
#
# Return values:
#   1 = success
#   0 = fail
#

sub check_net_list {
   my ($NET) = @_;

   foreach my $net_list_elem (@NET_list) {
      my $net_obj = Net::Netmask->new($net_list_elem);
      if (defined($net_obj->{'ERROR'})) {
         if (defined($option{'w'})) {
            close(HTML_FILE);
         }
         exit 1;
      }
      if ($net_obj->match($NET)) {
         return 1;
      }
   }
   return 0;
}

#-------------------------------------------------------------------------
# Name: check_filename
#
# Description: checks if filename contains expected characters only.
#
# Return values:
#   file = success
#   0    = fail -- file contains some characters that may lead
#                  to a security problem.
#

sub check_filename {
   my ($file) = @_;
   return $1 if ($file =~ /^([\w\-\:\_\.\/]+)$/);
   return 0;
}

#-------------------------------------------------------------------------
# Name: show_usage
#
# Description: print program usage and exit.
#
# Return values:
#    none
#

sub show_usage {
   print <<EOF;

Usage: $program_name -c honeydsum.conf [-hVw] log-file1 log-file2 ... log-filen
       -c   honeydsum.conf file.
       -h   display this help and exit.
       -V   display version number and exit.
       -w   display output as web page (HTML).
   
EOF

   exit 1;
}

#-------------------------------------------------------------------------
# Name: show_version
#
# Description: print program version and exit.
#
# Return values:
#    none
#

sub show_version {
   printf("$program_name: %s\n", $honeydsum_version);
   exit 0;
}

#---------------------------------------------------------------------
# Name: sanitize_ip
#
# Description: IP sanitize with base in address passed as parameter.
#
# Return values:
#   ip address sanitized
#

sub sanitize_ip {
   my ($ip_db) = $_[0];
   shift @_;
   my ($real_net_list, $fake_net_list) = @_;

   my (@real_net_list);
   my (@fake_net_list);
   my ($real_net_obj);
   my ($fake_net_obj);
   my ($real_net);
   my $i = 0;

   ### IP SRC ###
   foreach $real_net (@{$real_net_list}) {
      $real_net_obj = Net::Netmask->new($real_net);
      if (defined($real_net_obj->{'ERROR'})) {
         if (defined($option{'w'})) {
            close(HTML_FILE);
         }
         exit 1;
      }
      if ($real_net_obj->match($ip_db)) {
         $fake_net_obj = Net::Netmask->new(@{$fake_net_list}[$i]);
         if (defined($fake_net_obj->{'ERROR'})) {
            if (defined($option{'w'})) {
               close(HTML_FILE);
            }
            exit 1;
         }

         my $part_fake_net;
         if ($fake_net_obj->bits() <= 8) {
            $part_fake_net = substr(@{$fake_net_list}[$i],
               0, index(@{$fake_net_list}[$i], "\."))
              . substr($ip_db, index($ip_db, "\."), length($ip_db));
         } elsif ($fake_net_obj->bits() > 8 && $fake_net_obj->bits() <= 16) {
            $part_fake_net = substr(
               @{$fake_net_list}[$i],
               0,
               index(
                  @{$fake_net_list}[$i], "\.",
                  index(@{$fake_net_list}[$i], "\.") + 1
               )
              )
              . substr($ip_db, index($ip_db, "\.", index($ip_db, "\.") + 1),
               length($ip_db));
         } elsif ($fake_net_obj->bits() > 16 && $fake_net_obj->bits() <= 31) {
            $part_fake_net = substr(@{$fake_net_list}[$i],
               0, rindex(@{$fake_net_list}[$i], "\."))
              . substr($ip_db, rindex($ip_db, "\."), length($ip_db));
         } else {
            warn("$program_name: cannot sanitize: " . $ip_db . "\n");
            return $ip_db;
         }

         if ($fake_net_obj->match($part_fake_net)) {
            return $part_fake_net;
         } else {
            warn("$program_name: cannot sanitize: " . $ip_db . "\n");
            return $ip_db;
         }
      }    #end if
      $i++;
   }    #end for

   return $ip_db;
}

#---------------------------------------------------------------------
# Name: pie_total_graph
#
# Description: create the total connections graph per protocol
#
# Return values:
#    none
#

sub pie_total_graph {
   my $graph_name = $_[0];
   shift @_;
   my @parameter = @_;

   if ($#parameter != -1) {

      # Both the arrays should same number of entries.
      my @data = ([ 'TCP', 'UDP', 'ICMP' ], [ $_[0], $_[1], $_[2] ]);

      my $graph = new GD::Graph::pie(250, 250) || die GD::Graph::pie::error();

      $graph->set(
         title          => $graphics{$graph_name}->{'title'},
         dclrs          => [qw(lblue lgreen black)],
         transparent    => 1,
         axislabelclr   => 'white',
         '3d'           => $graphics{$graph_name}->{'3d'},
         start_angle    => 90,
         suppress_angle => 5,
        )
        || die $graph->error;

      $graph->set_value_font(GD::Font->MediumBold);
      $graph->plot(\@data) || die $graph->error;

      open(FIG_FILE, ">" . $output_html_dir . $graph_name . ".png")
        || die("$program_name: cannot open file.\n");
      binmode FIG_FILE;
      printf(FIG_FILE "%s", $graph->gd->png);
      close(FIG_FILE);
   }
}

#---------------------------------------------------------------------
# Name: bar_graph
#
# Description: create the bar graphic to top information
#
# Return values:
#    none
#

sub bar_graph {
   my $graph_name = $_[0];

   shift @_;
   my @parameter = @_;
   my $i         = 0;

   if ($graph_name =~ /^hour$/) {
      $i = -1;
   }
   if ($#parameter != -1) {

      # Both the arrays should same number of entries.
      my $datas;
      my @y_datas = ();
      my @x_datas = ();

      foreach $datas (@parameter) {
         push(@y_datas, $datas);
         push(@x_datas, (++$i));
      }

      my @data = ([@x_datas], [@y_datas]);

      my $graph;
      if ($graphics{$graph_name}->{'3d'}) {
         $graph = GD::Graph::bars3d->new(500, 300) || die GD::Graph::bars3d::error();
      } else {
         $graph = GD::Graph::bars->new(500, 300) || die GD::Graph::bars::error();
      }
      $graph->set(
         x_label => $graphics{$graph_name}->{'x_label'},
         y_label => $graphics{$graph_name}->{'y_label'},
         title   => $graphics{$graph_name}->{'title'},

         # Show values on top of each bar
         show_values => $graphics{$graph_name}->{'show_values'},
         box_axis    => 1,
        )
        || die $graph->error;

      my $image = $graph->plot(\@data) or die $graph->error;

      open(FIG_FILE, ">" . $output_html_dir . $graph_name . ".png")
        || die("$program_name: cannot open file.\n");
      binmode FIG_FILE;
      printf(FIG_FILE "%s", $image->png);
      close(FIG_FILE);
   }
}

#---------------------------------------------------------------------
# Name: main_graphics
#
# Description: create the other graphics
#
# Return values:
#    none
#

sub main_graph {
   my $graph_name = $_[0];

   my @data;

   my $graph;
   if ($graphics{$graph_name}->{'3d'}) {
      $graph = GD::Graph::bars3d->new(500, 300) || die GD::Graph::bars3d::error();
   } else {
      $graph = GD::Graph::bars->new(500, 300) || die GD::Graph::bars::error();
   }

   $graph->set(
      x_label => $graphics{$graph_name}->{'x_label'},
      y_label => $graphics{$graph_name}->{'y_label'},
      title   => $graphics{$graph_name}->{'title'},

      # Draw bars with width 3 pixels
      bar_width => 3,

      # Sepearte the bars with 4 pixels
      bar_spacing => 4,

      # Show the grid
      long_ticks => 0,

      # Show values on top of each bar
      show_values => $graphics{$graph_name}->{'show_values'},
     )
     || die $graph->error;

   $graph->set_legend_font(GD::Font->MediumBold);
   
   my @data_tmp = ();
   for (my $i = 0 ; $i <= $#ip_high ; $i++) {
      push(@data_tmp, $i + 1);
   }

   if ( $graph_name eq "honeypot_connections" ) {
      @data = ([@data_tmp], [@total_con]);
   } elsif ( $graph_name eq "honeypot_ips" ) {
      @data = ([@data_tmp], [@total_ips]);
   } elsif ( $graph_name eq "honeypot_ips" ) {
      @data = ([@data_tmp], [@total_ips]);
   } elsif ( $graph_name eq "honeypot_resources" ) {
      @data = ([@data_tmp], [@total_res]);
   } else {
      warn("$program_name: cannot define graphics: $graph_name \n");
   }

   ###############
   
   my $image = $graph->plot(\@data) || die $graph->error;

   open(FIG_FILE, ">" . $output_html_dir . $graph_name . ".png")
     || die("$program_name: cannot open file.\n");
   binmode FIG_FILE;
   printf(FIG_FILE "%s", $image->png);
   close(FIG_FILE);

}

#---------------------------------------------------------------------
# Name: hp_resources_graph
#
# Description: create Resources x Connections graphics per each
# honeypot
#
# Return values:
#    none
#

sub hp_resources_graph {
   my ($graph_name, $resource_sub) = @_;

   my %resource_hash_sub = %$resource_sub;

   my @data1 = ();
   my @data2 = ();
   foreach $resource (sort { $a <=> $b } keys %resource_hash_sub) {
      push(@data1, $resource);
      push(@data2, $resource_hash_sub{$resource});

   }
   my @data = ([@data1], [@data2]);

   my $graph = new GD::Graph::pie(250, 250) || die GD::Graph::pie::error();

   $graph->set(
      title => $graphics{'ip_a'}->{'title'},
      dclrs => [
         qw(blue green lorange dblue dgreen lred red dred purple dpurple orange marine lbrown dbrown black)
      ],
      transparent => 1,
      axislabelclr   => 'white',
      '3d'           => $graphics{'ip_a'}->{'3d'},
      start_angle    => 90,
      suppress_angle => 5,
     )
     || die $graph->error;

   $graph->set_value_font(GD::Font->MediumBold);

   $graph->plot(\@data) || die $graph->error;

   open(FIG_FILE, ">" . $output_html_dir . $graph_name . "_a.png")
     || die("$program_name: cannot open file.\n");
   binmode FIG_FILE;
   printf(FIG_FILE "%s", $graph->gd->png);
   close(FIG_FILE);
}

sub hp_source_ip_graph {
   my ($graph_name, $source_sub) = @_;
   my %source_hash_sub = %$source_sub;
   
   my $i = 1;
   my $src_ip_tmp;
   my $nbr_src_ip_tmp;

   my @data_tmp = ();
   my $counter_tmp = 0;

   my $data_new = GD::Graph::Data->new() || die GD::Graph::Data::error();

   $i = 0;
   foreach $nbr_src_ip_tmp (sort { $a <=> $b } keys %source_hash_sub) {
      $src_ip_tmp = join ".", unpack "C4", pack "N", $nbr_src_ip_tmp;

      $counter_tmp = 1;
      @data_tmp = ();
      while (my ($key, $value_tmp) = each(%{ $source_hash_sub{$nbr_src_ip_tmp} })) {
         push(@data_tmp, $value_tmp);
      }

      $data_new->set_x($i, $i + 1);
      foreach my $datas (@data_tmp) {
         $data_new->set_y($counter_tmp, $i, $datas);
         $counter_tmp++;
      }

      $i++;
   }

   $data_new->cumulate(1);

   my $graph;
   if ($graphics{'ip_b'}->{'3d'}) {
      $graph = GD::Graph::bars3d->new(500, 300) || die GD::Graph::bars3d::error();
   } else {
      $graph = GD::Graph::bars->new(500, 300) || die GD::Graph::bars::error();
   }

   $graph->set(
      x_label => $graphics{'ip_b'}->{'x_label'},
      y_label => $graphics{'ip_b'}->{'y_label'},
      title   => $graphics{'ip_b'}->{'title'},
      bar_spacing => 3,
      long_ticks  => 0,
      show_values => $graphics{'ip_b'}->{'show_values'},
      cumulate => 1,
   ) || die $graph->error;
   
   my $image = $graph->plot($data_new) or die $graph->error;

   open(FIG_FILE, ">" . $output_html_dir . $graph_name . "_b.png")
     || die("$program_name: cannot open file.\n");
   binmode FIG_FILE;
   printf(FIG_FILE "%s", $image->png);
   close(FIG_FILE);
}

#---------------------------------------------------------------------
# Name: parser_config_file
#
# Description: Parser option from config file
#
# Return values:
#   none
#

sub parser_config_file {

   my $file_tmp;

   if (!($file_tmp = &check_filename(@_))) {
      $file_tmp = quotemeta(@_);
      printf("$program_name: $file: invalid file name.\n");
      exit 1;
   }

   my $name;

   if ($file_tmp =~ /\.bz2$/) {
      $viewer = $bzcat;
   } elsif ($file_tmp =~ /\.gz$/) {
      $viewer = $zcat;
   } else {
      $viewer = $cat;
   }

   my @viewer_args = ();
   push(@viewer_args, $file_tmp);
   my $pid = open(CHILD_TO_READ3, "-|");

   if (!$pid) {
      # child
      exec($viewer, @viewer_args)
        || die("$program_name: $viewer: can't exec: $!\n");

      # never reached
   } else {

      # parent
      while (<CHILD_TO_READ3>) {
         chomp;       # no newline
         s/#.*//;     # no comments
         s/^\s+//;    # no leading white
         s/\s+$//;    # no trailing white
         
         s/\'//g;     # no trailing white
         s/\;//;      # no trailing white
         
         next unless length;    # anything left?
         my ($var, $value) = split(/\s*=\s*/, $_, 2);

         if ($var eq "honeyd_conf") {
            if ($value =~ /\S+/) {
               $honeyd_conf       = 1;
               @honeyd_conf_files = split(/\s*\,\s*/, $value);
            }
         } elsif ($var eq "institution_net") {
            # Real Institution Network Address
            if ($value =~ /\S+/) {
               my $real_net;
               @real_inst_net = split(/\s*\,\s*/, $value);

               foreach $real_net (@real_inst_net) {
                  $real_inst_net_obj = Net::Netmask->new($real_net);
                  if (defined($real_inst_net_obj->{'ERROR'})) {
                     exit 1;
                  }
               }
            }
         } elsif ($var eq "fake_honeypot_net") {
            # Fake Honeypot Network Address
            if ($value =~ /\S+/) {
               my $fake_net;
               @fake_hp_net = split(/\s*\,\s*/, $value);

               foreach $fake_net (@fake_hp_net) {
                  $fake_hp_net_obj = Net::Netmask->new($fake_net);
                  if (defined($fake_hp_net_obj->{'ERROR'})) {
                     exit 1;
                  }
               }
            }
         } elsif ($var eq "honeypot_list") {
            # List of honeypot's IP addresses
            if ($value =~ /\S+/) {
               @IP_list = &set_list("IP", $value);
               if ($#IP_list == -1) {
                  warn("$program_name: cannot set IP list.\n");
                  exit 1;
               }
            }
         } elsif ($var eq "net_list") {
            # source IP or Network addresses for filtering
            if ($value =~ /\S+/) {
               @NET_list = &set_list("NET", $value);

               if ($#NET_list == -1) {
                  warn("$program_name: cannot set IP or net list.\n");
                  exit 1;
               }
            }
         } elsif ($var eq "dest_port") {
            # List of destination ports
            if ($value =~ /\S+/) {
               @PORT_list = &set_list("PORT", $value);

               if ($#PORT_list == -1) {
                  warn("$program_name: cannot set port list.\n");
                  exit 1;
               }
            }
         } elsif ($var eq "real_honeypot_net") {
            # Real Honeypot Network Address
            if ($value =~ /\S+/) {
               my $real_net;
               @real_hp_net = split(/\s*\,\s*/, $value);

               foreach $real_net (@real_hp_net) {
                  $real_hp_net_obj = Net::Netmask->new($real_net);
                  if (defined($real_hp_net_obj->{'ERROR'})) {
                     exit 1;
                  }
               }
            }
         } elsif ($var eq "top_information") {
            # Number of records on top
            if ($value =~ /([0-9]+)/) {
               $top_show = $1 + 1;
            } else {
               warn("$program_name: cannot set top.\n");
               exit 1;
            }
         } elsif ($var eq "proto_list") {
            # List of protocols
            if ($value =~ /\S+/) {
               @PROTO_list = &set_list("PROTO", $value);

               if ($#PROTO_list == -1) {
                  warn("$program_name: cannot set protocol list.\n");
                  exit 1;
               }
            }
         } elsif ($var eq "fake_institution_net") {
            # Fake Institution Network Address
            if ($value =~ /\S+/) {
               my $fake_net;
               @fake_inst_net = split(/\s*\,\s*/, $value);

               foreach $fake_net (@fake_inst_net) {
                  $fake_inst_net_obj = Net::Netmask->new($fake_net);
                  if (defined($fake_inst_net_obj->{'ERROR'})) {
                     exit 1;
                  }
               }
            }
         } elsif ($var eq "html_file") {
            # HTML output file
            if ($value =~ /\S+/) {
               $output_html_file = $value;
            } else {
               if (defined($option{'w'})) {
                  warn("$program_name: you must inform html output file\n");
                  exit 1;
               }
            }
         } elsif ($var eq "name") {
            # Graphic's name
            if ($value =~ /\S+/) {
               $name = $value;
            } else {
               warn("$program_name: cannot set name: $value \n");
               exit 1;
            }
         } elsif ($var eq "type") {
            # Graphic's type
            if ($value =~ /^[pie|bar]/) {
               $graphics{$name}->{$var} = $value;
            } else {
               warn("$program_name: cannot set type: $value \n");
               exit 1;
            }
         } elsif ($var eq "title") {
            # Graphic's title
            if ($value =~ /\S+/) {
               $graphics{$name}->{$var} = $value;
            } else {
               warn("$program_name: cannot set title: $value \n");
               exit 1;
            }
         } elsif ($var eq "show") {
            # Show graphic
            if ($value =~ /^[y|n]$/) {
               $value eq 'y'
                 ? ($graphics{$name}->{$var} = 1)
                 : ($graphics{$name}->{$var} = 0);
            } else {
               warn("$program_name: cannot set show: $value \n");
               exit 1;
            }

         } elsif ($var eq "3d") {
            # Show graphic as 3d
            if ($value =~ /^[y|n]$/) {
               $value eq 'y'
                 ? ($graphics{$name}->{$var} = 1)
                 : ($graphics{$name}->{$var} = 0);
            } else {
               warn("$program_name: cannot set 3d: $value \n");
               exit 1;
            }

         } elsif ($var eq "show_values") {
            # Show graphic values
            if ($value =~ /^[y|n]$/) {
               $value eq 'y'
                 ? ($graphics{$name}->{$var} = 1)
                 : ($graphics{$name}->{$var} = 0);
            } else {
               warn("$program_name: cannot set show_values: $value \n");
               exit 1;
            }
         } elsif ($var eq "x_label") {
            # Graphic's x label
            if ($value =~ /\S+/) {
               $graphics{$name}->{$var} = $value;
            } else {
               warn("$program_name: cannot set x_label: $value \n");
               exit 1;
            }
         } elsif ($var eq "y_label") {
            # Graphic's y label
            if ($value =~ /\S+/) {
               $graphics{$name}->{$var} = $value;
            } else {
               warn("$program_name: cannot set y_label: $value \n");
               exit 1;
            }
         } else {
            warn("$program_name: cannot define value: $value \n");
            exit 1;
         }
      }
      close(CHILD_TO_READ3) || warn("$program_name: $viewer: exited $?\n");
   }

   # Comparing networks
   if ($#real_hp_net != $#fake_hp_net) {
      warn(
         "$program_name: real and fake honeypot network must have size equals\n"
      );
      exit 1;
   }

   if ($#real_inst_net != $#fake_inst_net) {
      warn(
"$program_name: real and fake institution network must have size equals\n"
      );
      exit 1;
   }

   # Checking institution sanitized network
   for (my $i = 0 ; $i <= $#real_inst_net ; $i++) {
      $real_inst_net_obj = Net::Netmask->new($real_inst_net[$i]);
      if (defined($real_inst_net_obj->{'ERROR'})) {
         exit 1;
      }
      $fake_inst_net_obj = Net::Netmask->new($fake_inst_net[$i]);
      if (defined($fake_inst_net_obj->{'ERROR'})) {
         exit 1;
      }
      if ($real_inst_net_obj->bits() != $fake_inst_net_obj->bits()) {
         warn(
"$program_name: real and fake institution network must have mask equals\n"
         );
         exit 1;
      }
   }

   # Checking honeypot sanitized network
   for (my $i = 0 ; $i <= $#real_hp_net ; $i++) {
      $real_hp_net_obj = Net::Netmask->new($real_hp_net[$i]);
      if (defined($real_hp_net_obj->{'ERROR'})) {
         exit 1;
      }
      $fake_hp_net_obj = Net::Netmask->new($fake_hp_net[$i]);
      if (defined($fake_hp_net_obj->{'ERROR'})) {
         exit 1;
      }
      if ($real_hp_net_obj->bits() != $fake_hp_net_obj->bits()) {
         warn(
"$program_name: real and fake honeypot network must have mask equals\n"
         );
         exit 1;
      }
   }
}

######################################################################
### honeydsum.pl ends here

