# (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
import honeyd
import re

def bad_request(mydata):
	mydata["write"] = ('HTTP/1.0 400 Bad Request\r\n'
			   '\r\n'
			   '<html><head>'
			   '<title>400 Bad Request</title>'
			   '</head><body>'
			   '<h1>Bad Request</h1>'
			   '<p>Your browser sent a request that this server'
			   ' could not understand.<br />'
			   '</p><hr /></body></html>')

def request(mydata, request, url):
	mydata["write"] = ('HTTP/1.0 200 OK\r\n'
			   '\r\n'
			   '<html><head><title>nothing</title></head>'
			   '<body></body></html>')
	
def honeyd_init(data):
	mydata = {}
	mydata['re_req'] = re.compile("^([A-Z]*)\s+/(.*)\s+HTTP/1.[01]")
	mydata['write'] = ''
	honeyd.read_selector(honeyd.EVENT_ON)
	honeyd.write_selector(honeyd.EVENT_OFF)
	return mydata

def honeyd_readdata(mydata, data):
	mydata["write"] += data
	data = mydata['write']
	if data.find('\r\n\r\n') >= 0:
		honeyd.write_selector(honeyd.EVENT_ON)
		res = mydata['re_req'].match(data)
		if not res:
			bad_request(mydata)
		else:
			request(mydata, res.group(1), res.group(2))
	elif (len(data) > 1000):
		honeyd.write_selector(honeyd.EVENT_ON)
		bad_request(mydata)
	else:
		honeyd.read_selector(honeyd.EVENT_ON)
	
	return 0

def honeyd_writedata(mydata):
	honeyd.write_selector(honeyd.EVENT_ON)
	if mydata.has_key("write"):
		data = mydata["write"]
		del mydata["write"]
		return data
	else:
		return None

def honeyd_end(mydata):
	del mydata
	return 0
