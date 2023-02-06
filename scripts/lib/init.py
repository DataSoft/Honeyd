import sys
import os

sys.path.append("/usr/share/honeyd/scripts/lib/")
from names import InitializeDB
from names import AddNames

home = os.path.expanduser("~")
InitializeDB(home + "/.config/honeyd/names")

try:
	self._os_chmod(home + "/.config/honeyd/names", 0666)
except OSError: pass

try: 
	self._os_chmod(self._file_name, 0777)
except OSError: pass