#!/usr/bin/env python
import sys
import os
import re
import glob
import stat

def recompute(dir):
  os.chdir(dir)
  os.system("aclocal")
  os.system("autoheader")
  os.system("automake")
  os.system("autoconf")
  os.system("../config.status")
  os.system("make dist")

  # the make is going to fail because there is no distribute
  os.system("rm -f *")
  os.system("cp -p %s/* ." % dir)
  os.system("rm -rf ./%s" % dir)

def remove_cut(filename):
  file = open(filename, "r")
  output = open(filename+".bak", "w")
  cut = 0
  for line in file:
    line = re.sub("hsniff", "", line)
    if re.match("^# <-- cut start -->", line):
      cut = 1
    elif cut:
      if re.match("# <-- cut end -->", line):
        cut = 0
    else:
      print >>output, line,

  file.close()
  output.close()

  os.rename(filename+".bak", filename)

def replace(filein, fileout):
  for line in filein:
    if re.search("<LICENSEHERE>", line):
	print >>fileout, license,
    else:
        print >>fileout, line,

def scandir(dir):
  for file in glob.glob('%s/*' % dir):
    if re.match("^.*/\..*", file):
      continue
    sb = os.lstat(file)
    if stat.S_IFMT(sb[0]) == stat.S_IFDIR:
	scandir(file)
	continue
    if not re.match("^.*\.[chyl]$", file):
	continue

    fin = open(file, "r")
    fout = open("%s.tmp" % file, "w")
    replace(fin, fout)
    fin.close()
    fout.close()
    os.rename("%s.tmp" % file, file)

# Main
if os.path.basename(os.getcwd()) != "honeyd":
  print >>sys.stderr, "DISTRIBUTE.PY ignored"
  sys.exit(0)

blurb = "LICENSE.blurb"
try:
	license = open(blurb, "r").read()
except:
	license = open("../" + blurb, "r").read()

m = re.compile("<!--.*-->\s*\*", re.MULTILINE|re.DOTALL)
license = m.sub(" *", license)

scandir(sys.argv[1])

remove_cut(sys.argv[1]+"/Makefile.am")

recompute(sys.argv[1])
