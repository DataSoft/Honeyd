import sys
import os

sys.path.append("/usr/share/honeyd/scripts/lib/")
from names import InitializeDB
from names import AddNames

home = os.path.expanduser("~")
InitializeDB(home + "/.config/honeyd/names")

try:
	os.chmod(home + "/.config/honeyd/names", 0666)
except:
	pass

try:
	os.chmod(home + "/.config/honeyd", 0777)
except:
	pass
