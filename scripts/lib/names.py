
#Returns the name that our IP address is allocated to in the names_alloc file
#	returns empty string if not present
def GetAllocatedName(names_path, our_IP):
	try:
		fd = open(names_path + "_alloc")
		line = fd.readline()
		while line:
			if(line.split(",", 1)[1] == our_IP):
				return line.split(",", 1)[0]
			line = fd.read
		return ""
	except IOError:
		return ""

#Searches for the given name in the names_alloc file
#	returns true is present, false if not
def IsAllocated(names_path, name):
	try:
		fd = open(names_path + "_alloc")
		line = fd.readline()
		while line:
			if(line.split(",", 1)[0] == name):
				return True
			line = fd.readline()
		return False
	except IOError:
		return False

#Picks the next name from the names file and allocates it to ourself
#	by adding an entry in the names_alloc file
#	returns the chosen name on success, empty string on failure
def AddNameAllocation(names_path, our_IP):
	try:
		fd = open(names_path)
		line = fd.readline()
		while line:
			if not IsAllocated(names_path, line):
				writeFD = open(names_path + "_alloc", "a")
				writeFD.write(line.rstrip('\n') + "," + our_IP)
				return line
			line = fd.readline()
		return ""
	except IOError:
		return ""
