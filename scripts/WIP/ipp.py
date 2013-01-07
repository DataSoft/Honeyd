#!/usr/bin/python

import binascii
import sys
import os
import urllib2
import socket
import argparse
from struct import pack, unpack

IPP_VERSION = "1.1"
IPP_PORT = 631

STATUS_CODES_SUCCESS = {"0x0000": "successful-ok", 
                        "0x0001": "successful-ok-ignored-or-substituted-attributes", 
                        "0x0002": "successful-ok-conflicting-attributes"}

STATUS_CODES_CLIENT_ERROR = {"0x0400": "client-error-bad-request", 
                             "0x0401": "client-error-forbidden", 
                             "0x0402": "client-error-not-authenticated", 
                             "0x0403": "client-error-not-authorized", 
                             "0x0404": "client-error-not-possible", 
                             "0x0405": "client-error-timeout", 
                             "0x0406": "client-error-not-found", 
                             "0x0407": "client-error-gone",
                             "0x0408": "client-error-request-entity-too-large", 
                             "0x0409": "client-error-request-value-too-long", 
                             "0x040A": "client-error-document-format-not-supported", 
                             "0x040B": "client-error-attributes-or-values-not-supported", 
                             "0x040C": "client-error-uri-scheme-not-supported", 
                             "0x040D": "client-error-charset-not-supported", 
                             "0x040E": "client-error-conflicting-attributes", 
                             "0x040F": "client-error-compression-not-supported", 
                             "0x0410": "client-error-compression-error", 
                             "0x0411": "client-error-document-format-error", 
                             "0x0412": "client-error-document-access-error"}

STATUS_CODES_SERVER_ERROR = {"0x0500": "server-error-internal-error", 
                             "0x0501": "server-error-operation-not-supported", 
                             "0x0502": "server-error-service-unavailable", 
                             "0x0503": "server-error-version-not-supported", 
                             "0x0504": "server-error-device-error", 
                             "0x0505": "server-error-temporary-error", 
                             "0x0506": "server-error-not-accepting-jobs", 
                             "0x0507": "server-error-busy", 
                             "0x0508": "server-error-job-canceled", 
                             "0x0509": "server-error-multiple-document-jobs-not-supported"}

class IPPResponseTCP :
  """Class for TCP responses to IPP requests."""
  #attributes_types = ("operation", "job", "printer", "unsupported", \
  #                                 "subscription", "event_notification")
  def __init__(self, data="", version=IPP_VERSION,
                              status_code=None, \
                              request_id=None, \
                              printattr=False, \
                              jobattr=False) :
    self._data = data
    self.parsed = False
    self.setVersion(version)
    self.setStatusCode(status_code)
    self.setRequestId(request_id)
    self.setPrintAttr(printattr)
    self.setJobAttr(jobattr)
    self.data = ""

    #for attrtype in self.attributes_types :
    #   setattr(self, "_%s_attributes" % attrtype, [[]])
    
    # Initialize tags    
    self.tags = [ None ] * 256 # by default all tags reserved
    
    self.tags[0x01] = "operation-attributes-tag"
    self.tags[0x02] = "job-attributes-tag"
    self.tags[0x03] = "end-of-attributes-tag"
    self.tags[0x04] = "printer-attributes-tag"
    self.tags[0x05] = "unsupported-attributes-tag"
    self.tags[0x21] = "integer"
    self.tags[0x22] = "boolean"
    self.tags[0x23] = "enum"
    self.tags[0x44] = "keyword"
    self.tags[0x45] = "uri"
    self.tags[0x46] = "uriScheme"
    self.tags[0x47] = "charset"
    self.tags[0x48] = "naturalLanguage"
    self.tags[0x49] = "mimeMediaType"
    
    # Reverse mapping to generate IPP messages
    self.tagvalues = {}
    for i in range(len(self.tags)) :
       value = self.tags[i]
       if value is not None :
         self.tagvalues[value] = i

  def setPrintAttr(self, newVal) :
    self.printAttr = newVal
    
  def setJobAttr(self, newVal) :
    self.jobAttr = newVal

  def setVersion(self, version) :
    """Sets the request's operation id."""
    if version is not None :
        try :
            self.version = [int(p) for p in version.split(".")]
        except AttributeError :
            if len(version) == 2 : # 2-tuple
                self.version = version
            else :    
                try :
                    self.version = [int(p) for p in str(float(version)).split(".")]
                except :
                    self.version = [int(p) for p in IPP_VERSION.split(".")]
      
  def setStatusCode(self, stcd) :        
    """Sets the request's operation id."""
    self.statusCode = stcd
      
  def setRequestId(self, reqid) :        
    """Sets the request's request id."""
    self.request_id = reqid.encode('hex')
    
  def generateResponse(self) :
    httprn = "0d0a"
    http = []
    # HTTP response code
    http.append("HTTP/1.1 200 OK".encode('hex'))
    http.append(httprn)
    # Server
    http.append("Server: Doopr".encode('hex'))
    http.append(httprn)
    # Transfer-Encoding
    http.append("Transfer-Encoding: chunked".encode('hex'))
    http.append(httprn)
    # Content-Type
    http.append("Content-Type: application/ipp".encode('hex'))
    http.append(httprn)
    # Cache-Control
    http.append("Cache-Control: max-age=3600, public".encode('hex'))
    http.append(httprn)
    http.append(httprn)
    # Chuck-Data
    # To get chunk size, we're going to have to generate the IPP header 
    # and determine how many bytes there are
    ipp = self.generateIPP()
    # which happens here. But, there's a twist: for some reason, the
    # length given in the header is given as a hex string, not just a 
    # hex value -- i.e. it'll be 0x0041 but they'll want "30303431" 
    stringifylength = "{0:08X}".format(int(hex(len(ipp) / 2), 16))
    chunklength = ""
    for c in stringifylength :
        chunklength += "".join("{0:02X}".format(int(hex(ord(c)), 16)))
    http.append(chunklength)
    http.append(httprn)
    http.append(ipp)
    http.append(httprn)
    http.append("{0:02X}".format(int("0", 16)))
    http.append(httprn)
    http.append(httprn)
    return "".join(http)
    
  def generateIPP(self) :
    """Generates the hex for the response (WIP)."""
    if self.statusCode in STATUS_CODES_SUCCESS :
      return STATUS_CODES_SUCCESS[self.statusCode]
    elif self.statusCode in STATUS_CODES_CLIENT_ERROR or self.statusCode in STATUS_CODES_SERVER_ERROR :
      packet = []
      """All of the IPP Response REQUIRED attributes are constructed here"""
      packet.append("{0:02X}".format(self.version[0]))
      packet.append("{0:02X}".format(self.version[1]))
      packet.append("{0:04X}".format(int(self.statusCode, 16)))
      packet.append("{0:08X}".format(int(self.request_id, 16)))
      packet.append("{0:02X}".format(self.tagvalues["operation-attributes-tag"]))
      packet.append("{0:02X}".format(self.tagvalues["charset"]))
      packet.append("{0:04X}".format(int(hex(len("attributes-charset")), 16)))
      packet.append("attributes-charset".encode('hex'))
      packet.append("{0:04X}".format(int(hex(len("us-ascii")), 16)))
      packet.append("us-ascii".encode('hex'))
      packet.append("{0:02X}".format(self.tagvalues["naturalLanguage"]))
      packet.append("{0:04X}".format(int(hex(len("attributes-natural-language")), 16)))
      packet.append("attributes-natural-language".encode('hex'))
      packet.append("{0:04X}".format(int(hex(len("en-us")), 16)))
      packet.append("en-us".encode('hex'))
      """If we're responding with the printer attributes data, construct here"""
      if self.printAttr : 
        packet.append("{0:02X}".format(self.tagvalues["printer-attributes-tag"]))
        packet.append("{0:02X}".format(self.tagvalues["enum"])) # Tag
        packet.append("{0:04X}".format(int(hex(len("printer-state")), 16))) # Name length
        packet.append("printer-state".encode('hex')) # Name
        packet.append("{0:04X}".format(int("0x0004", 16))) # Value length
        packet.append("{0:08X}".format(int("0x00000003", 16))) # Value
        packet.append("{0:02X}".format(self.tagvalues["keyword"])) # Tag
        packet.append("{0:04X}".format(int(hex(len("printer-state-reasons")), 16))) # Name length
        packet.append("printer-state-reasons".encode('hex')) # Name
        packet.append("{0:04X}".format(int(hex(len("none")), 16))) # Value length
        packet.append("none".encode('hex')) # Value
        packet.append("{0:02X}".format(self.tagvalues["mimeMediaType"])) # Tag
        packet.append("{0:04X}".format(int(hex(len("document-format-supported")), 16))) # Name length
        packet.append("document-format-supported".encode('hex')) # Name
        packet.append("{0:04X}".format(int(hex(len("text/plain")), 16))) # Value length
        packet.append("text/plain".encode('hex')) # Value
        packet.append("{0:02X}".format(self.tagvalues["boolean"]));
        packet.append("{0:04X}".format(int(hex(len("printer-is-accepting-jobs")), 16))) # Name length
        packet.append("printer-is-accepting-jobs".encode('hex')) # Name
        packet.append("{0:04X}".format(int("0x0001", 16))) # Value length
        if self.statusCode == "0x0506" : 
          packet.append("{0:02X}".format(int("0", 16))) # Value
        else :
          packet.append("{0:02X}".format(int("1", 16)))
      packet.append("{0:02X}".format(self.tagvalues["end-of-attributes-tag"]))
      return "".join(packet)
    else :
      return "STATUS CODE NOT RECOGNIZED"

class IPPResponseUDP :
  """Class for UDP responses to IPP requests."""


"""if __name__ == "__main__" :
  parser = argparse.ArgumentParser()
  parser.add_argument('-s', '--status-code', help='What IPP Response status code to return', required=True)
  parser.add_argument('-r', '--request-id', help='The IPP Request\'s request ID', required=True)
  parser.add_argument('-p', '--printer-attr', help='If used, the response will include the printer-attributes-tag section with bogus data')
  parser.add_argument('-j', '--job-attr', help='If used, the response will include the job-attributes-tag section with bogus data (NOT USED)')
  args = parser.parse_args()
  
  statuscode = args.status_code
  requestid = args.request_id
  if args.job_attr != None :
    jobattrarg = True
  else :
    jobattrarg = False
  if args.printer_attr != None :
    printattrarg = True
  else :
    printattrarg = False
    
  req = IPPResponseTCP(status_code=statuscode, request_id=requestid, printattr=printattrarg, jobattr=jobattrarg)
  print req.generateResponse()"""
