import sys
import os

sys.path.append("/usr/share/honeyd/scripts/lib/")
from names import InitializeDB

home = os.path.expanduser("~")
InitializeDB(home + "/.config/honeyd/names")
os.chmod(home + "/.config/honeyd/names", 0666)
