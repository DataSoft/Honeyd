import sqlite3
import os
import sys

#Returns the name that our IP address is allocated to
#	returns empty string if not present
def GetAllocatedName(names_path, our_IP):
	conn = InitializeDB(names_path)
	cursor = conn.cursor()
	cursor.execute("SELECT * FROM allocs WHERE IP=?", [our_IP])
	row = cursor.fetchone()
	if(row is None):
		return ""
	conn.close()
	return row[1].encode('ascii','ignore')

#Picks the next name from the names db and allocates it to ourself
#	by adding an entry in the names_alloc file
#	returns the chosen name on success, empty string on failure
def AddNameAllocation(names_path, our_IP):
	conn = InitializeDB(names_path)
	cursor = conn.cursor()

	#Check if we've already got a name for this IP
	name = GetAllocatedName(names_path, our_IP)
	if(name != ""):
		return name
	
	# Get an exclusive lock on the database
	conn.isolation_level = 'EXCLUSIVE'
	conn.execute('BEGIN EXCLUSIVE')

    # Some other script instance could have already got us a hostname. Check again now that we have exclusive lock.
	cursor.execute("SELECT * FROM allocs WHERE IP=?", [our_IP])
	row = cursor.fetchone()
	if(row is not None):
		conn.close()
		return row[1].encode('ascii','ignore')
		
	#Get an unused name
	cursor.execute("SELECT * FROM allocs WHERE IP is NULL")
	row = cursor.fetchone()
	if row is None:
		conn.close();
		sys.stderr.write("Unable to assign hostname to honeypot. No unused hostnames configured.\n")
		return ""
	name = row[1]
	cursor.execute("UPDATE allocs SET IP=? WHERE name=?", [our_IP, name])
	conn.commit()
	conn.close()
	return name.encode('ascii','ignore')

#Add a list of new names to the names db
def AddNames(names_path, names):
	conn = InitializeDB(names_path)
	cursor = conn.cursor()
	for name in names:
		try:
			cursor.execute("INSERT INTO allocs(name) VALUES (?)", [name])
		except sqlite3.IntegrityError:
			pass
	conn.commit()
	conn.close()

def InitializeDB(names_path):
	if not os.path.exists(os.path.dirname(names_path)):
		os.makedirs(os.path.dirname(names_path))
	conn = sqlite3.connect(names_path)
	cursor = conn.cursor()
	cursor.execute("select tbl_name from sqlite_master")
	list_tables = cursor.fetchone()
	if list_tables is None:
		cursor.execute("CREATE TABLE allocs (IP text UNIQUE, name text PRIMARY KEY)")
		conn.commit()
		return conn
	list_tables = list_tables[0]
	if("allocs" not in list_tables):
		cursor.execute("CREATE TABLE allocs (IP text UNIQUE, name text PRIMARY KEY)")
	conn.commit()
	return conn

