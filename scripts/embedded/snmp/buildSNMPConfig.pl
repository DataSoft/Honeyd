#! /usr/bin/perl


print "\n\n[frenchhoneynet] ********************************************************************\n";
print "[frenchhoneynet] Honeyd SNMP module configuration builder\n";

if(!$ARGV[0]) { print "[frenchhoneynet] usage : buildSNMPConfig.pl <honeyd config file>\n\n"; exit; }

die "[frenchhoneynet] no config file $ARGV[0] : $!\n\n" unless open(CONFIG,$ARGV[0]);

my @templates;
while(my $tpl = <*.snmp.tpl>)  {
	my($tpl_name) = $tpl =~ /(.*)\.snmp\.tpl$/;
         push(@templates,$tpl_name);
}

my %hosts;

while(my $line = <CONFIG>) {
	if(my($host,$personality) = $line =~ /set\s+(\S+)\s+personality\s+\"(.*)\"/) {
         	if(!defined($hosts{$host})) {
                 	my @tmp = ($personality,"127.0.0.1");
                         $hosts{$host} = \@tmp;
                 } else { @{$hosts{$host}}[0,1] = ($personality,"127.0.0.1"); }
         } elsif(my($ip,$host) = $line =~ /bind\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)/) {
                 if(!defined($hosts{$host})) {
                 	my @tmp; $tmp[2] = ($ip);
                         $hosts{$host} = \@tmp;
                 } else { push(@{$hosts{$host}},$ip); }
         }
}

close(CONFIG);

while(my($host,$values) = each(%hosts)) {
	print "[frenchhoneynet] ********************************************************************\n";
	print "[frenchhoneynet] Configure SNMP for $host with personality ".${@$values}[0]." [Y/n] : ";
         my $yn = <STDIN>;
         next if $yn =~ /n/i;
         print "[frenchhoneynet] Choose SNMP Template : \n";
         for(my $i=0;$i<=$#templates;$i++) { print " "x(20)."[$i] ".$templates[$i]."\n"; }
         my $tpl_num = 1000;
         while($tpl_num > $#templates || $tpl_num < 0) {
         	print	"[frenchhoneynet] Your template choice [0] : ";
                 $tpl_num = <STDIN>;
                 chop($tpl_num);
         }
         my $template = $templates[$tpl_num].".snmp.tpl";
         print "[frenchhoneynet] Building config file for : ".${@$values}[2]."\n";
         my $configfile = ${@$values}[2].".snmp";
         if(open(TPL,$template) && open(NEW,">".$configfile)) {
         	my @ips;
         	for(my $i=2;$i<=$#{@$values};$i++) { push(@ips,${@$values}[$i]); }
         	while(my $line = <TPL>) {
                 	$line =~ s/\#IP\#/${@$values}[2]/g;
                         if($line =~ /\#IPCONFIG\#/) {
                         	print NEW ".1.3.6.1.2.1.4.20.1.1.127.0.0.1 = IpAddress: 127.0.0.1\n";
                                 foreach(@ips) { print NEW ".1.3.6.1.2.1.4.20.1.1.$_ = IpAddress: $_\n"; }
				print NEW ".1.3.6.1.2.1.4.20.1.2.127.0.0.1 = INTEGER: 1\n";
				foreach(@ips) { print NEW ".1.3.6.1.2.1.4.20.1.2.$_ = INTEGER: 16777219\n"; }
				print NEW ".1.3.6.1.2.1.4.20.1.3.127.0.0.1 = IpAddress: 255.0.0.0\n";
				foreach(@ips) {  print NEW ".1.3.6.1.2.1.4.20.1.3.$_ = IpAddress: 255.255.255.0\n"; }
				print NEW ".1.3.6.1.2.1.4.20.1.4.127.0.0.1 = INTEGER: 1\n";
				foreach(@ips) { print NEW ".1.3.6.1.2.1.4.20.1.4.$_ = INTEGER: 1\n"; }
				print NEW ".1.3.6.1.2.1.4.20.1.5.127.0.0.1 = INTEGER: 65535\n";
				foreach(@ips) { print NEW ".1.3.6.1.2.1.4.20.1.5.$_ = INTEGER: 65535\n"; }
                         } else { print NEW $line; }
                 }
         	close(TPL);
                 close(NEW);
         } else { print "[frenchhoneynet] Error while creating a file... : $!\n"; }
         if($#{@$values} > 2) {
         	for(my $i=3;$i<=$#{@$values};$i++) {
                 	print "[frenchhoneynet] Copying config for : ".${@$values}[$i]." : ";
                         my $anotherconfigfilebutsimilar = ${@$values}[$i].".snmp";
                         if(symlink($configfile,$anotherconfigfilebutsimilar)) { print "ok\n"; }
                         else { print "nok... to bad! ($!)\n"; }
                 }
         }

}


print "[frenchhoneynet] ********************************************************************\n";
print "[frenchhoneynet] Done\n";












