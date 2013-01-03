#!/usr/bin/python

import sys
import os
import urllib2
import socket
from struct import pack, unpack

IPP_VERSION = "1.1"
IPP_PORT = 631

IPP_URL = 0x00
IPP_PROTO = 0x01
IPP_REQUEST_ID = 0x02
IPP_STATUS_CODE = 0x04

# successful-ok, successful-ok-ignored-or-substituted-attributes, successful-ok-conflicting-attributes
STATUS_CODES_SUCCESS = [0x0000, 0x0001, 0x0002]
# client-error-bad-request, client-error-forbidden, client-error-not-authenticated, client-error-not-authorized, client-error-not-possible, client-error-timeout, client-error-not-found, client-error-gone, client-error-request-entity-too-large, client-error-request-value-too-long, client-error-document-format-not-supported, client-error-attributes-or-values-not-supported, client-error-uri-scheme-not-supported, client-error-charset-not-supported, client-error-conflicting-attributes, client-error-compression-not-supported, client-error-compression-error, client-error-document-format-error, client-error-document-access-error
STATUS_CODES_CLIENT_ERROR = [0x0400, 0x0401, 0x0402, 0x0403, 0x0404, 0x0405, 0x0406, 0x0407
, 0x0407, 0x0408, 0x0409, 0x040A, 0x040B, 0x040C, 0x040D, 0x040E, 0x040F, 0x0410, 0x0411, 0x0412]
# server-error-internal-error, server-error-operation-not-supported, server-error-service-unavailable, server-error-version-not-supported, server-error-device-error, server-error-not-accepting-jobs, server-error-busy, server-error-job-canceled, server-error-multiple-document-jobs-not-supported
STATUS_CODES_SERVER_ERROR = [0x0500, 0x0501, 0x0502, 0x0503, 0x0504, 0x0505, 0x0506, 0x0507, 0x0508, 0x0509]

for i in range(0, sys.argv.__len__()):
  print sys.argv[i]

statuscode = sys.argv[0]
requestid = sys.argv[1]

req = IPPRequest(status_code=statuscode, \
                 request_id=requestid)
print req.generateMessage(0x0000)


class IPPResponseTCP :
  """Class for TCP responses to IPP requests."""
  """attributes_types = ("operation", "job", "printer", "unsupported", \
                                     "subscription", "event_notification")"""
  def __init__(self, data="", version=IPP_VERSION,
                              status_code=None, \
                              request_id=None) :
    self._data = data
    self.parsed = False
    self.setVersion(version)
    self.setStatusCode(status_code)
    self.setRequestId(request_id)
    self.data = ""

    """for attrtype in self.attributes_types :
        setattr(self, "_%s_attributes" % attrtype, [[]])
    
    # Initialize tags    
    self.tags = [ None ] * 256 # by default all tags reserved
    
    self.tags[0x01] = "operation-attributes-tag"
    self.tags[0x02] = "job-attributes-tag"
    self.tags[0x03] = "end-of-attributes-tag"
    self.tags[0x04] = "printer-attributes-tag
    self.tags[0x05] = "unsupported-attributes-tag"
    self.tags[0x06] = "attributes-charset"
    self.tags[0x07] = "attributes-natural-language"
    self.tags[0x47] = "charset"
    self.tags[0x48] = "naturalLanguage"
    
    # Reverse mapping to generate IPP messages
    self.tagvalues = {}
    for i in range(len(self.tags)) :
        value = self.tags[i]
        if value is not None :
            self.tagvalues[value] = i"""

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
    self.setStatusCode = stcd
      
  def setRequestId(self, reqid) :        
    """Sets the request's request id."""
    self.request_id = reqid

  def __getattr__(self, name) :                                 
    """Fakes attribute access."""
    if name in self.attributes_types :
        return FakeAttribute(self, name)
    else :
        raise AttributeError, name

  def generateMessage(self, statusCode) :
    if statusCode in STATUS_CODES_SUCCESS
      return "SUCCESS"
    else if statusCode in STATUS_CODES_CLIENT_ERROR
      return "CLIENT_ERROR"
    else if statusCode in STATUS_CODE_SERVER_ERROR  
      return "SERVER_ERROR"

class IPPResponseUDP :
  """Class for UDP responses to IPP requests"""


