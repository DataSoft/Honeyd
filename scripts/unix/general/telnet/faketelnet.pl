#!/usr/bin/perl
#Program the emulate the Telnet Server
#By Daniel B. Cid (daniel@underlinux.com.br / daniel@opensolutions.com.br)
#ITs under GNU
#You can use as you want.


require 'msgs.txt';

use IO::Socket;

my ($line, $i, $con, $port);

socket(SERVER, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or die "socket: $!";
setsockopt(SERVER, SOL_SOCKET, SO_REUSEADDR, 1) or die "setsockopt: $!";
bind(SERVER, sockaddr_in(24, INADDR_ANY)) or die "bind: $!";
listen(SERVER, SOMAXCONN) or die "listen: $!";


while($con = accept(CLIENT, SERVER))
		{
		$pid=fork();
	   	if ($pid == 0) 
			{
			addloginfo();
			login(CLIENT);
			}
		}


##Subrotina de login
sub login
        {
        ($client) = @_;
        send($client, "$message\n", 0);
        send($client, "\nLogin:", 0);
        recv(CLIENT, $user, 100, 0);
        if(length($user) > 15)
                {
                send($client, "Segment Fault\n", 0);
                $shell="sh-2.05b# ";
                &shell($client,$user);
                }
        chomp($user);
        send($client, "Password:", 0);
        recv(CLIENT, $pass, 100, 0);
	
	addloguser($user,$pass);
        shell($client,$user);
        }


##subrotina simulando uma shell
sub shell
        {
        getcmds();
        ($client,$user)= @_;
	my $steps="$user" . "conectou";
        send($client, "$shell", 0);
		my $exec=0;
                for(;;)
                {
                recv($client, $comand, 100, 0);
                chomp($comand);

		if($comand =~ /^\r/)
			{
			send($client, "$shell", 0);
			}
		elsif($comand =~ /quit\b/)
			{
			exit 0;
			}
		elsif($comand =~/\W/) 
			{
                	foreach my $rule (keys %cmds)
                        	{
                        	if($comand =~ /$rule/i)
                                	{
                                	send($client, "$cmds{$rule}", 0);
                                	send($client, "$shell", 0);
                                	$exe=1;
					last;
                                	}
				else
					{
					$exe=0;
					}
				}
               		if($exe != 1)
                        	{
				send($client, "bash command not found\n", 0);
                        	send($client, "$shell", 0);
                        	$exe=0;
                        	}
			}
                }
	exit 1;
        }


#subrotina que "pega" os comandos do arquivo cmds.txt

sub getcmds
        {
        open(CMDS, "cmds.txt");
                while (defined ($opt=<CMDS>))
                        {
			if($opt =~ /^ $/)
				{
				last;
				}
			else
				{
                        	@optw = split(/:/, $opt);
                        	$cmds{$optw[0]}=$optw[1];
				}
                        }
                close(CMDS);
                }

sub addloginfo
	{
	my($port,$iaddr) = sockaddr_in($con);
	open(LOGFILE, "+>>$logfile");
	if(LOGFILE)
		{
		print(LOGFILE scalar localtime);
		print(LOGFILE " Faketelnet  -- ataque vindo de: ", inet_ntoa($iaddr), ":$port\n");
		close(LOGFILE);
		}
	}

sub addloguser
	{
	my ($user,$pass)= @_;
	open(LOGFILE, "+>>$logfile");
	if(LOGFILE)
		{
		chomp($user);
		chomp($pass);
		print(LOGFILE "     Info do atacante:", $user, "\n");
		print(LOGFILE "     senha utilizada:", $pass, "\n");
		close(LOGFILE);
		}
	}


