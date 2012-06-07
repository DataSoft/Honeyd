#!/usr/bin/env python
#
# Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
import os
import sys
import regress
import time
import re

def get_ipaddr(count):
    octet1 = count % 254
    octet2 = count / 254

    return "10.0.%d.%d" % (octet2 + 1, octet1 + 1)

def nmap(count):
    ipaddr = get_ipaddr(count)

    log = open("/tmp/nmap.log", "a")
    file = os.popen('nmap -S 127.0.0.1 -e lo0 -sS -O -p1,23 %s 2>/dev/null' % ipaddr)

    oses = ""

    output = ""
    for line in file:
#        if re.match("^(SInfo|TSeq|T[0-9]|PU)", line):
        output += line
        res = re.match("OS (guesses|details): (.*)", line)
        if res:
            oses = res.group(2)
        elif re.match("^No exact OS", line):
            oses = None

    res = 0
    if oses:
        if oses == prints[count]:
            print "+",
            res = 1
        elif oses.find(prints[count]) != -1:
            print "-",
            res = 2
        else:
            print "?",
            print >>log, "Wanted: '%s' but got '%s':\n%s" % \
                  (prints[count], oses, output)
            failures.append("%d:" % count + prints[count] + oses + ":\n" + output)
    else:
        print >>log, "Wanted: '%s' but got nothing:\n%s" % \
              (prints[count], output)
        failures.append("%d:" % count + prints[count] + "No match:\n" + output)
        print "_",

    sys.stdout.flush()
    file.close()
    log.close()
    return res
    
def make_configuration(filename, fingerprints):
    output = open(filename, "w")
    input = open(fingerprints, "r")

    print >>output, """create template
set template default tcp action reset
add template tcp port 23 open
"""
    count = 0
    r = re.compile('\s*$')
    m = re.compile("^Fingerprint ([^#]*)$")
    for line in input:
        line = r.sub("", line)
        res = m.match(line)
        if not res:
            continue

        fname = res.group(1)

        prints[count] = fname
        ipaddr = get_ipaddr(count)

        # Create template
        print >>output, 'bind %s template' % ipaddr
        print >>output, 'set %s personality "%s"' % (ipaddr, fname)

        count += 1

    output.close()
    input.close()

    return count

# Main

failures = []
prints = {}

number = make_configuration("config.nmap", "../nmap.prints")

reg = regress.regress("Nmap fingerprints", "../honeyd", "config.nmap")
reg.start_honeyd(reg.configuration)

reg.fe.read()

success = 0
partial = 0
nothing = 0
for count in range(0, number):
    res = nmap(count)
    if res == 1:
        success += 1
    elif res == 2:
        partial += 1
    else:
        nothing += 1
    reg.fe.read()

reg.stop_honeyd()

print "\nSuccesses: %d, Partials: %d, Nothing: %d of %d" % (success, partial, nothing, number)
for line in failures:
    print line
