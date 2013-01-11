#!/usr/bin/python

import binascii
import sys
import os
import re
import subprocess
from struct import pack, unpack

if __name__ == "__main__" :
  if len(sys.argv) < 2 :
    sys.exit(1)

  ip = sys.argv[1]
  f = open('test.' + ip + '.txt','w')
  f.write(subprocess.check_output(["snmpwalk","-Cc","-Os","-c","public","-v","1",str(ip)],
                          stderr=subprocess.STDOUT))
  
  