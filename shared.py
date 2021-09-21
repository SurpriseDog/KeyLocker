#!/usr/bin/python3
# Shared variables

import sys
import random
import shutil
from functools import partial
from importlib.util import find_spec

from sd.common import rfs, warn, undent

# Check for required packages.
# Not in main because otherwise package import errors would yield this unreachable
# todo add instructions tested on more distros
if not all([find_spec(modname) for modname in ['readchar', 'argon2', 'psutil', 'Crypto']]):
	warn('Missing required python modules')
	print("\nHow to install modules for script to function:")
	print(undent('''
		sudo apt update
		sudo apt install python3-distutils python3-setuptools python3-dev gcc
		pip3 --version || sudo python3 -m easy_install install pip
		... or alternatively try: sudo apt install python3-pip

		sudo python3 -m pip install setuptools argon2 readchar xlib psutil pycrypto
	'''.strip(), tab=' '*4))
	raise ImportError



#Edianness of bytes
BYTEORDER = 'little'

#Future: implement this for windows
PLATFORM = sys.platform.lower()

#Terminal width
TERM_WIDTH = max(shutil.get_terminal_size().columns, 20)

#Gigabytes vis Binary Gigabtyes
BINARY_PREFIX = 1024 if PLATFORM.startswith('win') else 1000
rfs = partial(rfs, mult=BINARY_PREFIX)


#Set to use hash_mouse by main
MOUSE_HASHER = None



# Better random number generator that uses /dev/urandom:
# https://docs.python.org/3/library/random.html#random.SystemRandom
rand = random.SystemRandom()
