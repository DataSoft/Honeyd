# ============================================================================
#  Name        : nbns-wpad-query.py
#  Copyright   : DataSoft Corporation 2011-2013
# 	Nova is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
# 
#    Nova is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
# 
#    You should have received a copy of the GNU General Public License
#    along with Nova.  If not, see <http://www.gnu.org/licenses/>.
#  Description : Simple broadcast script that does a WPAD nbns query
# ============================================================================

import sys
import struct
import random

returnString = ""

# Transaction ID (random)
returnString += struct.pack('>H', random.randint(0, 65535))

# Flags (name query)
returnString += struct.pack('>H', 0x0110);

# Questions (1)
returnString += struct.pack('>H', 1);

# Answer RRs (0)
returnString += struct.pack('>H', 0);

# Authority RRs (0)
returnString += struct.pack('>H', 0);

# Additional RRs (0)
returnString += struct.pack('>H', 0);

# Query for WPAD<00> (Workstation/Redirector)
returnString += struct.pack('>33s', " FHFAEBEECACACACACACACACACACACAAAA");
returnString += struct.pack('>B', 0);

# Type (NB)
returnString += struct.pack('>H', 0x0020);

#Class (IN)
returnString += struct.pack('>H', 1);

sys.stdout.write(returnString);
sys.exit(0);
