#!/usr/bin/env python
#
# Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
# Honeyd Regression Framework Class
#
import os
import sys
import getopt
import popen2
import time
import fcntl
import string
import re
import dpkt
import pcap
import dnet
import tempfile # Note, we use mkstemp which is only available in 2.3
import filecmp

class Test:
    def __init__(self):
        # Precheck
        self.name = "<Unknown>"
        self.expect = None
        self.packets = []

        self.Setup()

    def Expect(self):
        return self.expect

    def Name(self):
        return self.name

    def Send(self):
        ip = dnet.ip()

        for pkt in self.packets:
            data = str(pkt)
            data = dnet.ip_checksum(data)
            ip.send(data)
            time.sleep(0.10)

class regress:
    def __init__(self, name, cmd, config, debug=0):
        self.testname = name
        self.debug = debug
        self.config = config
        self.cmd = cmd
	self.oktests  = 0
	self.runtests = 0
        self.generate = 0
        self.pidfile  = '/var/run/honeyd.pid'
        self.interface = self.find_loopback()
        try:
            os.stat(self.cmd)
	except OSError:
            print >>sys.stderr, 'Cannot find honeyd program "%s" ' % self.cmd
	    sys.exit(1)

        # XXX - we might need to add other configuration file options in here,
        # in order to avoid it using installed configuration files
        # (in Debian under /etc/honeypot/)
        self.command = ('%s --disable-webserver --disable-update -R 1 -d '
                        '-i %s -f %s 192.18.0.0/15') % (
            self.cmd, self.interface, '%s')
	try:
            os.stat(self.config)
	except OSError:
            print >>sys.stderr, (
                'Configuration file "%s" does not exist, aborting.' %
                self.config )
	    sys.exit(1)
        # Test the configuration file
        if self.testconfig(self.cmd, self.config) != 0:
            print >>sys.stderr, 'Cannot use file "%s", aborting,' % self.config
            sys.exit(1)
            
        self.regexps = [ [re.compile(r'\['), r'\['],
                         [re.compile(r'\('), r'\('],
                         [re.compile(r'\.'), r'\.'],
                         [re.compile(r'\]'), r'\]'],
                         [re.compile(r'\)'), r'\)'],
                         [re.compile(r'\*'), r'.*'],
                         [re.compile(r'\?'), r'.'],
                         [re.compile(r'\s+'), r'\s+']
                         ]
        if self.VerifyRoute() != 0:
	    print >>sys.stderr, 'There was an error adding the route'

        print >>sys.stderr, 'Testing "%s" behavior:' % self.testname

    def find_cmd(self,cmd):
    	""" Find the cmd binary of the running system """
        dirs = [ '/', '/usr/', '/usr/local/', sys.prefix ]
	for d in dirs:
		for sd in ('bin', 'sbin'):
			for name in ('dnet', 'dumbnet'):
				location = os.path.join(d, sd, cmd)
				if os.path.exists(location):
					return location
        return 0

    def find_loopback(self):
        """ Find which is the loopback interface in this system, use
        dnet for that
        """

        ifs = dnet.intf()

        interfaces = []
        ifs.loop(lambda x,y: interfaces.append(x), None)

        for intf in interfaces:
            if intf['flags'] & dnet.INTF_FLAG_LOOPBACK:
                if self.debug:
                    print >>sys.stderr, 'Loopback interface: ', intf['name']
                return intf['name']

        if self.debug:
            print >>sys.stderr, 'Failed to find loopback interface'

        return None

    def find_running_proc(self, name):
        # XXX - is this portable enough?
        file = os.popen("ps -o pid=,command= 2>/dev/null", 'r')
        # XXX - we only read a line, but there might be more than
        # one instances there
        for line in file:
            res = re.search('\s*(\d+) %s' % name, line)
            if res:
                return int(res.group(1))
        return None

    def AddRoute(self, network, gw):
        """Verifies that the route points to localhost."""
        network = dnet.addr(network)
        gw = dnet.addr(gw)

        router = dnet.route()

        error = 0
        try:
            res = router.delete(network)
        except OSError:
            if self.debug:
                print >>sys.stderr, "Cannot remove route: ", network

        try:
            res = router.add(network, gw)
        except OSError:
            if self.debug:
                print >>sys.stderr, "Cannot add route: ", network
            error = 1

	if error:
	    return 1
	else:
	    return 0

    def VerifyRoute(self):
        """ Adds the test routes, currently reserved by the RFC:
            network equiment test network - 192.18.0.0/15 and
            'test net' network            - 192.0.2.0/24
        """
        if self.AddRoute('192.0.2.0/24', '127.0.0.1'):
            return 1
        if self.AddRoute('192.18.0.0/15', '127.0.0.1'):
            return 1
        return 0

    # XXX - what's the method for destructing objects? we should
    # call this there to cleanup
    def RemoveRoute(self, network):
        """Removes the route pointing to localhost."""

        network = dnet.addr(network)
        router = dnet.route()

        error = 0
        try:
            res = router.delete(network)
        except OSError:
            if self.debug:
                print >>sys.stderr, "Cannot remove route: ", network
            error = 1

	if error:
	    return 1
	else:
	    return 0

    def RemoveAllRoutes(self):
        """Removes all the routes."""
        self.RemoveRoute('192.0.2.0/24')
        self.RemoveRoute('192.18.0.0/15')

    def match(self, got, should):
	if filecmp.cmp(got,should):
		return 1
	else:
# If we are debugging go finegrain, read the files and compare them
                if self.debug:
                    gotr = open(got)
                    shouldr = open(should)
                    count = 0
                    lineg = "start" 
                    lines = "start"
                    while len(lineg) and len(lines):
                        lineg = gotr.readline() 
                        lines = shouldr.readline()
                        count +=1
                        if lineg != lines:
                            print "Differ on line %d" % count
                            print "-%s", lines.splitlines()
                            print "+%s", lineg.splitlines()
        return 0
	
# XX we already use filecmp and compare line by line but this might be
# useful if we want to have regular expressions in the output files
#        tcpdump = self.tcpfr.read()
#        self.tcpdump = []
#        for line in string.split(tcpdump, '\n'):
#            if not len(line):
#                continue
#            self.tcpdump.append(line)
#        tcpdumperr = self.tcpfe.read()
#        self.tcpfr.close()
#        self.tcpfe.close()


    def fail(self):
        print >>sys.stderr, 'FAILED'
# XXX - We might not want to fail here, we will count the tests when ok()
        sys.exit(1)

    def ok(self):
        """ Print the final result of tests """
        if self.runtests == self.oktests:
            print >>sys.stderr, '  OK (%d)' % self.oktests
            sys.exit(0)
        else:
            failed = self.runtests-self.oktests
            print >>sys.stderr, '  FAILED (%u/%u)' % (failed, self.runtests)
            sys.exit(1)

    def finish(self):
	""" Finishes the tests, prints the results and removes the routes """
	self.RemoveAllRoutes()
        if not self.generate:
            self.ok()

    def testconfig(self, cmd, config):
        command = ('%s --disable-webserver --disable-update --verify-config '
                   '-i %s -f %s 192.18.0.0/15 >/dev/null 2>&1') % (cmd, self.interface, config)
        if self.debug:
            print >>sys.stderr, 'Running "%s"' % command
        errorcode = os.system(command)

        if self.debug and errorcode != 0:
            print 'Error testing honeyd configuration file returned: ', errorcode
        return errorcode


    def run(self, test):
        self.stop_honeyd()
        self.start_pcap()
        self.start_honeyd(self.config)
        self.outputfile = test.Expect()
        print >>sys.stderr, '\tRunning %s: ' % test.Name(),
        self.runtests +=1
        sys.stderr.flush()

        # Send all the packets
        test.Send()

        time.sleep(1)
        self.stop_honeyd()
        self.stop_pcap()
        if not self.generate:
            if self.compare() == 0:
                print >>sys.stderr, 'OK'
                self.oktests += 1
                # Clean up the temporary file unless debugging
                if not self.debug:
                    try:
                        os.remove(self.dpktfile)
                    except IOError:

                        print >>sys.stderr, "Expected temporary file %s does not exist" % self.dpktfile
        else:
           # We want to use the results we generated instead of comparing them
           if self.Rename(self.dpktfile, self.outputfile):
               print >>sys.stderr, "Cannot move over the auto-generated file"
               sys.exit(1)
           print >>sys.stderr, "Generated output file '%s'" % self.outputfile

    def Rename(self, src, dst):
        try:
            error = 0
            os.rename(src, dst)
        except OSError:
            if self.debug:
                print >>sys.stderr, "Rename %s -> %s failed" % (src, dst)
            error = 1

        if not error:
            return 0

        # Open and copy
        error = 0
        try:
            data = open(src, 'r').read()
            open(dst, 'w').write(data)
        except OSError:
            error = 1

        if error:
            return 1
        else:
            return 0

    def compare(self):
    	try:
    		os.stat(self.outputfile)
	except OSError:
            print >>sys.stderr, 'Expected results file "%s" not found' % self.outputfile
            self.fail()
            return 1
    	try:
		os.stat(self.dpktfile)
	except OSError:
            print >>sys.stderr, 'We lost the file with the output "%s"!' % self.dpktfile
            self.fail()
            return 1

	if os.stat(self.dpktfile).st_size != os.stat(self.outputfile).st_size:
# Not a direct failure, but worth mentioning
	    if self.debug:
	            print >>sys.stderr, 'Results are of different length'

 	if not self.match(self.dpktfile,self.outputfile):
            if self.debug:
	  	    print >>sys.stderr, 'Results differ'
            self.fail()
            return 1

# If we get here comparison is OK
        return 0

    def set_nonblock(self, fd):
        # set it to non-blocking mode
        flags = fcntl.fcntl (fd, fcntl.F_GETFL, 0)
        flags = flags | os.O_NONBLOCK
        fcntl.fcntl (fd, fcntl.F_SETFL, flags)

    def start_honeyd(self, filename):
        (fw, fr, self.fe) = popen2.popen3(self.command % filename, 0)

        fw.close()
        fr.close()
        self.set_nonblock(self.fe.fileno())
        time.sleep(2)

    def start_pcap(self):
	(self.dpktfh, self.dpktfile) = tempfile.mkstemp()
	if self.debug:
            print "Starting pcap capture, saving in file", self.dpktfile
	self.pid_pcap = os.fork()
	if self.pid_pcap == 0:
            # Child, reads pcap, outputs to a file in dpkt format
            pc = 0
            try:
		pc = pcap.pcap(self.interface)
            except:
                print >>sys.stderr, "Cannot run packet filter, aborting"
                sys.exit(1)
            
            # filter on our dedciated subnets
            pc.setfilter('net 192.18.0.0/15 and net 192.0.2.0/24') 
            for ts, pkt in pc:
                lp = dpkt.loopback.Loopback(pkt)
                ip = dpkt.ip.IP(str(lp.data))
                os.write(self.dpktfh, "SRC=" + dnet.ip_ntoa(ip.src) + "\n")
                os.write(self.dpktfh, "DST=" + dnet.ip_ntoa(ip.dst) + "\n")
                os.write(self.dpktfh, "ID=%d\n" % ip.id)
                os.write(self.dpktfh, "TTL=%d\n" % ip.ttl)
                os.write(self.dpktfh, "DATA=" + `ip.data` + "\n")
                os.write(self.dpktfh, "\n")
            exit
            # Parent returns
        return 0

        
    def kill_pid(self, pid):
        if self.debug:
            print  >>sys.stderr, "Killing honeyd pid:", pid
        try:
            os.kill(int(pid), 2)
            return 0
        except OSError:
            return 1

    def exists_pid(self, pid):
        # XXX - is this portable enough?
        file = os.popen("ps -o pid= -p %s" % pid, 'r')
        pid = file.readline()
        file.close()
        if len(pid):
            return True
        else:
            return False

    def stop_honeyd(self):
        pid = 0
        try:
            pid = open(self.pidfile, 'r').read()
        except IOError:
	    if self.debug:
                print  >>sys.stderr, "No honeyd pidfile"

        if pid != 0:
            if self.exists_pid(pid):
                show_error = self.kill_pid(pid)
                # XXX that might not be us!
                try:
                    self.honeyd = self.fe.read()
                    if show_error:
                        print "Failed to kill honeyd: ", self.honeyd
                        # Close all file descriptors
                        self.fe.close()
                except:
                    if self.debug:
                        print >>sys.stderr, "Killed an instance of honeyd we did not run"
                # Clean up the file
            try:
                os.remove(self.pidfile)
            except:
                print >>sys.stderr, "Cannot remove pidfile"
                sys.exit(1)
        else:
        # Hmmm, me don't have a pid, is there another honeyd running?
            pid = self.find_running_proc('honeyd')
            if pid:
                self.kill_pid(pid)

    def stop_pcap(self):
        time.sleep(1)
	if self.debug:
            print "Killing pcap capture, pid:", self.pid_pcap
        os.kill(self.pid_pcap, 9)
        time.sleep(1)

    def usage():
         print "Usage: %s [-d]" % sys.argv[0]
