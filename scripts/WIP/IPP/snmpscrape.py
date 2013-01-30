#!/usr/bin/python

import binascii
import sys
import os
import re
import argparse
import math
import subprocess
import xml.etree.ElementTree as xmlm

def indent(elem, level=0, step=0):
  """
    As the xml.etree.ElementTree lib doesn't have a pretty 
    print function, we are forced to make do. 
  """
  i = '\n' + (level * '\t')
  if len(elem):
      if not elem.text or not elem.text.strip():
          elem.text = i + '\t'
      if not elem.tail or not elem.tail.strip() and step != 0:
          elem.tail = i
      for elem in elem:
          indent(elem, level + 1, step + 1)
      if not elem.tail or not elem.tail.strip():
          elem.tail = i
  else:
      if level and (not elem.tail or not elem.tail.strip()):
          elem.tail = i
          
def modtype(type, line):
  """
    Convert the SNMP defined types into the values within the
    self-tags array in ipp.py.
  """
  retType = ''
  if type == 'STRING' or type == 'Hex-STRING':
    retType = 'octet-string'
  elif type == 'INTEGER':
    retType = 'integer'
  elif type == 'IpAddress':
    retType = 'ip-address'
  elif type == 'OID':
    retType = 'object-identifier'
  elif type == 'Gauge32':
    '''
      The Gauge32 and Counter32 variable types are the SNMP v2
      versions of Gauge and Counter. Currently, the two sets are 
      in different dictionaries within ipp.py, but until I can
      find a device that responds to v2c or v3 requests with the v2c+ 
      variable types, both are going to return the SNMP v1 types.
    '''
    retType = 'gauge'
  elif type == 'Gauge':
    retType = 'gauge'
  elif type == 'Counter32':
    retType = 'counter'
  elif type == 'Counter':
    retType = 'counter'
  elif type == 'Timeticks':
    retType = 'timeticks'
  else:
    retType = 'octet-string'
    #retType = 'null'
    
  return line.replace(type, retType)

def getLongFormEncoding(value):
  """
    This method will convert an integer to its long-form
    encoding counterpart according to the SNMP BER. The 
    rules for this are thus:
    
      - The MSB of a byte is used to indicate whether the 
      parser at the other end is to read the next byte as 
      another part of the integer or not.
      
      - Only 7 bits can be used to represent an integer.
      
      - For every byte that gets added on, the value of that
      byte is multiplied by 2 ^ (7 * i), where 'i' is the
      level of significance (i.e. if we have a two byte 
      integer, the first byte will be multiplied by 128
      and then get added to the next to calculate the 
      result.
  """
  retlist = []
  j = 1
  while (2 ** (7 * j)) < value:
    j += 1
  bytenum = j
  for i in reversed(range(0, bytenum)):
    test = 0x00
    mult = (2 ** (7 * i)) if i > 0 else 1
    while True:
      test += 0x01
      if (test * mult) > value:
        test -= 0x01
        break
    add = 0x80 if i > 0 else 0x00
    retlist.append('{0:02X}'.format(int(hex(test), 16) | add))
    value -= test * mult
  return ''.join(retlist)

def convertDotsToHex(oid):
  """
    This function will convert a dot-decimal format string into its 
    corresponding hex representation, using the long form encoding if
    needed.
  """
  oidBER = []
  oidBER.append('{0:02X}'.format(0x2B))
  split = oid.split('.')
  upperlimit = 126
  for j in range(2, len(split)):
    if int(split[j], 10) > upperlimit:
      oidBER.append(getLongFormEncoding(int(split[j], 10)))
    else:
      hexchar = hex(int(split[j], 10))[2:]
      if len(hexchar) % 2 == 1:
        hexchar = '0' + hexchar
      oidBER.append(hexchar)
  return ''.join(oidBER).upper()

if __name__ == '__main__':
  ip = ''
  ofilename = ''
  matchname = ''
  #scriptname = ''
  keep = False

  temp = os.getenv('HOME') + '/.config/nova/config/templates/scripts.xml'

  prefix = os.getenv('HOME') + '/.config/honeyd/IPP/'
  
  if not os.path.exists(prefix):
    try:
      os.makedirs(prefix)
    except IOError as e:
      print 'Could not make directory ' + prefix + ': ' + e.strerror
      sys.exit(1)
    except OSError as e:
      print 'Directory ' + prefix + ' exists'

  parser = argparse.ArgumentParser(description='snmpwalk an IP address for its MIB data within the 1.3.6.1.2 and 1.3.6.1.4 subtrees, and create a CSV file for honeyd scripts to use.')
  parser.add_argument('-i', '--ip', help='The IP Address for snmpscrape to get MIB data from', required=True)
  parser.add_argument('-o', '--ofile', help='The name of the output file for the CSV MIB data. snmpscrape adds ".txt" to the end automatically. Preferred value is an absolute path name of $HOME/.config/honeyd', required=True)
  parser.add_argument('-n', '--name', help='Name of the script in $NOVA_HOME/config/templates/scripts.xml to make the results of snmpscrape available to', nargs='*')
  #parser.add_argument('-r', '--results-name', help='Required in conjunction with -n. The value for this argument will be the name of the device placed in the scripts file', nargs='*')
  parser.add_argument('-p', '--script-path', help='Used in confunction with -n. Path to Nova scripts.xml file (defaults to $HOME/.config/nova/config/templates/scripts.xml', default=temp)
  parser.add_argument('-k', '--keep', help='Keep the results of snmpwalk in addition to the restructured output. Takes no value', action='store_true')

  args = parser.parse_args(sys.argv[1:])

  # Assign command line values to proper variables
  # Also do some auditing to make sure that -n and -r are
  # both there if one is found. If only one is present,
  # there is an error. I thought there would be something 
  # within the python argparse lib to help with dependent
  # arguments, but they only consider mutually exclusive ones.
  ip = args.ip
  ofilename = prefix + args.ofile
  if args.keep:
    keep = True
  if args.name: # and args.results_name:
    matchname = ' '.join(args.name)
    #scriptname = ' '.join(args.results_name)
  #else:
    #parser.error('If -n is used, -r RESULTS_NAME must be supplied as well')
  if args.script_path:
    scriptpath = args.script_path
    
  # Write out the outputs of the 1.3.6.1.2 subtree and the 1.3.6.1.4
  # subtree of the target ip address
  path = prefix + 'temp.' + ip + '.txt'
  f = open(path,'w+')
  f.write(subprocess.check_output(['snmpwalk','-Cc','-Os','-c','public','-v','1',str(ip),'1.3.6.1.2'],
                          stderr=subprocess.STDOUT))
  f.flush()
  f.write(subprocess.check_output(['snmpwalk','-Cc','-Os','-c','public','-v','1',str(ip),'1.3.6.1.4'],
                          stderr=subprocess.STDOUT))
  f.close()
  f = open(path, 'r')
  restructure = f.readlines()
  if restructure[-1] == 'End of MIB\n':
    del restructure[-1]
  
  try:
    replacement = open(ofilename + '.txt', 'w+')
  except IOError as e:
    print 'Could not open file ' + ofilename + ': ' + e.strerror
    sys.exit(1)
    
  # In this block, we're restructuring the lines returned from snmpwalk 
  # to be consistent with the values and names used in the ipp.py script
  for line in restructure:
    writeline = line.replace('iso', '1')
    writeline = writeline.replace('=', ':')
    splitline = writeline.split(':')
    for i in range(0, len(splitline)):
      splitline[i] = splitline[i].strip()
      
    splitline[0] = convertDotsToHex(splitline[0])
    # Timeticks has a special format in the returned info for snmpwalk.
    # Something like (#########) Date Conversion
    # However, the only information being sent within the packet is 
    # the value within the parens.
    if splitline[1] == 'Timeticks':
      split = splitline[2].split(' ')
      splitline[2] = split[0].replace('(', '').replace(')', '')
      while len(splitline) > 3:
        del splitline[-1]
      splitline[2] = hex(int(splitline[2], 10))[2:]
      hexrange = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
                  'A', 'B', 'C', 'D', 'E', 'F', 'a', 'b', 'c', 'd', 'e', 'f']
      if splitline[2][-1] not in hexrange:
        splitline[2] = splitline[2][0:-1]
      if len(splitline[2]) % 2 == 1:
        splitline[2] = '0' + splitline[2]
    # Since OID BER encoding is a bit mathematically heavy-handed,
    # do it here. This will take an OID in the format 1.3.6.1.{...}
    # and turn it into a hex string of 2B{...}.
    elif splitline[1] == 'OID':
      if splitline[2] == 'ccitt.0':
        splitline[2] = '00'
      else:
        splitline[2] = convertDotsToHex(splitline[2])
    # We want to convert an IpAddress in dot-decimal format into
    # four hex pairs in one string
    elif splitline[1] == 'IpAddress':
      split = splitline[2].split('.')
      ipBER = []
      for i in range(0, len(split)):
        ipBER.append('{0:02X}'.format(int(hex(int(split[i], 10)), 16)))
      splitline[2] = ''.join(ipBER)
    # STRINGs take the form "some-string", we want to take the value
    # inside the quotes and encode it into hex.
    elif splitline[1] == 'STRING':
      split = splitline[2].split('"')
      splitline[2] = split[1].encode('hex')
    # For hex strings, the values are going to be stored
    # as a string representation of the hex. Just need to use 
    # binascii.a2b_hex(hexstring) to get the binary values for
    # the response packet
    elif splitline[1] == 'Hex-STRING':
      split = ''.join(splitline[2].split(' '))
      splitline[2] = split
    elif (splitline[1] == 'INTEGER' or splitline[1] == 'Gauge' or splitline[1] == 'Gauge32'
         or splitline[1] == 'Counter' or splitline[1] == 'Counter32'):
      if int(splitline[2], 10) < 0:
        splitline[2] = hex(0xff - int(hex(math.trunc(math.fabs(int(splitline[2], 10) + 1))), 16))[2:]
      else:
        splitline[2] = '00' + hex(int(splitline[2], 10))[2:]
      hexrange = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
                  'A', 'B', 'C', 'D', 'E', 'F', 'a', 'b', 'c', 'd', 'e', 'f']
      if splitline[2][-1] not in hexrange:
        splitline[2] = splitline[2][0:-1]
      if len(splitline[2]) % 2 == 1:
        splitline[2] = '0' + splitline[2]
    # There are some OIDs that return nothing, shown in the 
    # snmpwalk return text as "". For this return value, wireshark
    # shows the packet as having a varbind id of 0x04 (octet-string)
    # and a length of 0x00. 
    elif splitline[1] == "\"\"":
      splitline[1] = 'octet-string'
    writeline = ','.join(splitline) + '\n'
    writeline = modtype(splitline[1], writeline)
    replacement.write(writeline)
    
  f.close()
  replacement.close()
  if keep == False:
    os.remove(path)
    
  # This block of code is for adding an option, key, and/or value to 
  # the scripts XML for the designated script. Essentially, given the
  # -r (results name) and -n (script name) flags, create an option 
  # if there isn't one, create a key if there isn't one, and add a 
  # value for the given arg. If the value exists (i.e. all the information
  # the user passed is in place) it'll do nothing. 
  
  # So, without further ado, the comments. If we were provided values for
  # the -r and -n flag
  if matchname != '':# and scriptname != '':
    # Convert the scriptname into a list to audit for characters.
    # As I am not yet completely comfortable with the way python does
    # its regex stuff, I'm doing a character by character audit to ensure
    # there's no special characters that would cause a problem in the XML.
    """
      audit = list(scriptname)
      for c in range(0, len(audit)):
        # If it's not alphanumeric or a space, make it an underscore
        if re.match('[0-9a-zA-Z ]', audit[c]) == None:
          audit[c] = '_'
      scriptname = ''.join(audit)
    """
    # Parse the scripts.xml file
    tree = xmlm.parse(scriptpath)
    # and get the root node
    root = tree.getroot()
    # Initialize some variables that'll be used later
    found = False
    option = ''
    key = ''
    value = ''
    # Iterate through all of the <script> tags in scripts.xml
    for child in root.findall('script'):
      # If we find a script tag whose name is the name of the 
      # script the user designated on the command line, continue.
      # Otherwise, keep going.
      if child[0].text == matchname:
        # Search for the configurable tag. Technically, the absense
        # of this tag means that the scripts.xml is broken, but 
        # error checking for that would be under the bailiwick of
        # some auditing tool, not here. If it's not there, add it.
        configurable = child.find('configurable')
        if configurable != None:
          configurable.text = 'true'
        else:
          configurable = xmlm.SubElement(child, 'configurable')
          configurable.text = 'true'
        # If we don't find an option tag, then this script was
        # not set to be configurable before snmpscrape ran. 
        # Create it if it isn't there, or assign the node to 
        # the variable option if it is
        if child.find('option') == None:       
          option = xmlm.SubElement(child, 'option')
        else:
          option = child.find('option')
        # If there's no child <key> of option, add one
        # and give it the tentative value 'DEVICE_TYPE'
        if option.find('key') == None:
          key = xmlm.SubElement(option, 'key')
          key.text = 'DEVICE_TYPE'
        # Before we add the value, we need to check that it isn't
        # already represented in the value list. If there aren't any 
        # values, it will add after the for loop fails to iterate
        checknorepeats = option.findall('value')
        addvalue = True
        for elem in checknorepeats:
          if elem.text == ofilename:
            addvalue = False
        if addvalue:
          value = xmlm.SubElement(option, 'value')
          value.text = ofilename
        #xmlm.dump(child)
        # Prettify the output to the file.
        indent(child, 1)
        #xmlm.dump(child)
        # Write out to scripts.xml
        tree.write(scriptpath)
        # Set found to true so as not to trigger the warning below
        # after successful execution.
        found = True
    if not found:
      print 'The script name that you entered does not exist. Aborting...'
  
  
  