#!/usr/bin/python3

import os
import sys
import system
import shared


import sd.easy_args as easy_args

from sd.common import is_num, uerror as error, get_blocksize, bisect_small, round_up, round_down
from sd.common import warn, rfs, strip_punct, sort_dict, ConvertDataSize, mrfs, query, randint



ISROOT = bool(os.geteuid() == 0)	# Running from sudo?

DEFAULT_MEM = 3 * 1024**3
# Default memory size of 3 GiB
# Most users have more than 3GB installed as of 2020
# https://www.memorybenchmark.net/amount-of-ram-installed.html

def parse_args():
	am = easy_args.ArgMaster(usage="./keylocker.py <keyfile> <device_name> --options...",
	                          newline='\n'*2, verbose=False)

	pos_args = [\
		['datafile_name'],
		"Name of the datafile to use.",
		['devname'],
		'''Name of the device to use (optional)
		or type: "biggest" to automatically select the largest device''',
		]
	am.update(pos_args, 'Positional Arguments:', positionals=True)


	mode_args = [\
		('write', '', bool),
		"Write to datafile",

		('read', '', bool),
		"Read from datafile",
		]
	am.update(mode_args, 'Mode Arguments:')


	basic_args = [\
		# Format:
		# (alias, variable_name, type, default)
		# "help string"

		("create", "create_mapper", list, None),
		'''Create a new device mapper: --create <start> <end> <name>
		Example: --create="80%+10G -1M" will create a mapping
		starting at 80% of the device plus 10 gigabytes and
		ending with 1 megabyte to spare before the end of the device''',

		("insecurepass", "insecure_pass", str, ''),
		'''Useful for bash scripts with keyfiles.
		Password security is minimal if anyone else has access to your machine.
		Security comes from salt files. Overrides other options''',

		("tries", "password_tries", int, 15),
		"How many times to ask for the password in read mode",

		("wipe", "wipe_on_max_tries", bool),
		"Wipe the data file if password is repeatedly wrong.",

		('verbose', '', int, 1),
		"Verbosity level",

		('mapper', 'mapper_name'),
		"Encrypted device mapper. Example: /dev/mapper/????",

		("batch", "batch_mode", bool),
		"Batch mode, disables prompts and animation",

		("noshamir", "shamir_mode", bool),
		"Reverts to simple mode",

		('nomouse', 'disable_mouse', bool),
		"Don't run hash_mouse.py to get generate additional randomness",
		]
	am.update(basic_args, 'Optional Arguments:')


	salt_args = [\
		("salt", "salt_files", list),
		"Salt files or directories",

		("generate", "create_salt_list", list),
		"Create salt files: <directory> <count> <size> <name>",
		]
	am.update(salt_args, "Salt Files:\n" + \
	                     "  Optional files that are hashed with the password. Must be the same each time!")


	advanced_args = [\
		# Warning! These must be identical each time the program runs.

		("mem", "hash_mem", str),
		'''Argon2 hash memory in GiB.
		For computers with less than 4GB, half the ram will be used.
		Default: '''+ mrfs(DEFAULT_MEM),

		#("target", "target_hash_time", float, 4),
		#"Adjust the hash time to try and hit this number in seconds",

		("rounds", "hash_rounds", int, 4),
		"Number of rounds to use.",

		("threads", "hash_threads", int, 64),
		"Number of concurrent cpu threads to use. " + \
		"Using more threads than you have cpu threads available doesn't seem " + \
		"to impact performance up to about 64x as many threads as actual cpu cores.",
		# Setting this number high for future compatability.
		# 256 threads on 4 cores showed a 9% slowdown,
		# 64 threads on 4 cores shows only a 1% slowdown,
	]
	am.update(advanced_args, "Advanced Arguments:\n" +\
	                         "  Changing these affects Argon2 hashing, so they must be the same each time!\n")


	test_args = [\
		# Hidden args for development use

		("print", "print_table", bool),
		"Print the dmsetup table with visible keys",

		("devmode", '', bool),
		"Disable ceratin warnings",

		("visualize", "visual_data", bool),
		"Show log base 256 of byte values as they are used",
		]

	am.update(test_args, "Used for testing purposes:", hidden=True)


	return am.parse(wrap=100)


def process_mapper_args(args, blocksize):
	'''Go through an argstring for create_mapper like
	80%+10G -1M and produce the correct sector boundaries.
	/dev/sda1 -1M will return the end sector of sda1 and then the next whole MiB
	Returns [start, end] sectors'''


	if len(args) == 1:
		args = args[0].split()

	def convert(arg, pos):
		"pos is the beginning or end of the device"
		cds = ConvertDataSize(blocksize=blocksize, binary_prefix=shared.BINARY_PREFIX, rounding=4096)
		val = 0

		# Look for devices to convert to sector numbers
		if '/' in arg:
			if '+' in arg:
				arg = arg.split('+')
				dev = arg[0]
				arg = arg[1]
			elif '-' in arg:
				arg = arg.split('-')
				dev = arg[0]
				arg = '-' + arg[1]
			else:
				dev = arg
				arg = ''

			val += system.start_end(dev)[pos]

		if is_num(arg):
			val += int(arg)
		else:
			val += cds(arg)
		return val



	if blocksize >= 10e6:
		print("Endpoint wasn't specified so a random endpoint was chosen to not clobber last 1KB of partition")
		end = blocksize - randint(1024, 1024*64)
	else:
		end = blocksize

	if len(args) == 0:
		offset = 0
	if len(args) >= 1:
		offset = convert(args[0], 1)
	if len(args) >= 2:
		end = convert(args[1], 0)
	if len(args) >= 3:
		warn("Too many arguments in:", ' '.join(args))
		error('''Expected format: --create <start> <end>
				 Example: --create 10%+2G -3M creates a mapper starting at
				 10% + 2 gigabytes and ending 3 megabytes before the end of the drive.''')



	# Convert to sectors:
	offset = round_up(offset, 1024**2) // 512
	end = round_down(end, 1024**2) // 512
	print('Create mapper:', args)
	print('Size:        ', rfs((end - offset) * 512))
	print('Start sector:', offset)
	print('End sector:  ', end)
	print()

	if end <= offset:
		error("End sector must be after start sector")
	if not query("Is this okay?"):
		sys.exit(1)

	return offset, end - offset


def calc_mem(gigs):

	minimum = 1024**2
	# User specified number:
	if gigs:
		if is_num(gigs):
			gigs = gigs + 'g'
		# Convert user memory size to whole MiB
		mem = ConvertDataSize(binary_prefix=1024)(gigs) // minimum * minimum
		if mem < minimum:
			mem = minimum
			print("Minimum memory value is:", mrfs(minimum))
		if mem >= system.mem_total():
			error("Asked for", mrfs(mem), 'but only', mrfs(system.mem_total()), 'memory available')
		return mem


	# Otherwise assume default
	if system.mem_total() > DEFAULT_MEM:
		return DEFAULT_MEM
	else:
		warn("Not enough memory to use the default of:", mrfs(DEFAULT_MEM))
		warn("If you upgrade the ram in this computer you can pass the old size manually with --mem")
		gigs = system.mem_total()
		sizes = [2**x * 1024**2 for x in range(64)]		# Allowed sizes from 1 MiB to 8 YiB
		mem = sizes[bisect_small(sizes, gigs)]
		warn("\tUsing memory size:", mrfs(mem), "(Write this down)")
		return mem

	'''Take in memory size in integer GiB and return bytes
	If gigs < 1, step down by half for each -1, Minimum is 1 MiB
	Future: Round down mem to power of 2
	if gigs >= 1:
		mem = gigs * 1024**3
	else:
		mem = (1024 // 2**(1 - gigs)) * 1024**2
	if mem < 1024**2:
		mem = 1024**2
	if verbose >= 2 or gigs < 1:
		print("Using memory size:", mrfs(mem))
	return mem
	'''

def get_mode(user_args):
	ua = user_args

	if ua.read and not ua.write:
		return 'read'
	if ua.write and not ua.read:
		return 'write'
	if ua.read and ua.write:
		error("You must select only to read or write from datafile")

	# Otherwise guess program mode, read or write to datafile
	if ua.devname:
		mode = 'read'
	else:
		mode = 'write'

	if ua.mapper_name:
		mode = 'write'

	if ua.create_mapper:
		mode = 'write'

	if mode == 'read':
		print("Assuming mode: read from datafile")
	else:
		print("Assuming mode: write to datafile")
	return mode



def get_args(testing=False):
	"Get user args and do some processing to make sure everything is okay"
	ua = parse_args()

	#Root check
	if ua.devname and not ISROOT:
		error("NOT RUNNING AS ROOT. Cannot access device:", ua.devname)

	#Select the biggest device in the system
	if strip_punct(ua.devname.strip().lower()) == 'biggest':
		ua.devname = os.path.join('/dev', sort_dict(system.get_partitions())[-1][0])
		print("Using biggest device:", ua.devname)

	#Check that the device name exists
	if ua.devname and not os.path.exists(ua.devname):
		error(ua.devname, 'does not exist')

	# Show the arguments:
	if ua.verbose >= 2:
		easy_args.show_args(ua)


	#Determine program mode:
	ua.mode = get_mode(ua)

	#If datafile is a folder, put a file in that folder.
	if os.path.isdir(ua.datafile_name):
		ua.datafile_name = os.path.join(ua.datafile_name, 'KeyFile.KL')

	#convert memory
	ua.hash_mem = calc_mem(ua.hash_mem)


	blocksize = None
	#Parse create_mapper_args
	if ua.create_mapper == []:
		ua.create_mapper = '0'

	if ua.create_mapper:
		# if 'mapper' in ua.devname.lower():
		#	print('Word: mapper found in device name')
		#	error("Usage is: /keylocker.py <keyfile> <device_name> <optional: mapper_name> --create")

		if ua.devname:
			if ISROOT:
				blocksize = get_blocksize(ua.devname)
			elif testing:
				warn("NOT RUNNING AS ROOT. Cannot access device:", ua.devname)
			else:
				error("Must be running as root to acess:", ua.devname)

		else:
			if testing:
				warn("No device name given")
			else:
				error('''Create_mapper requires a device name like /dev/sd???
						 You can pass one with ./keylocker.py <keyfile> <device_name> --create...''')
		if blocksize is None and testing:
			print("Using blocksize of 1 Gigabyte for testing purposes")
			blocksize = int(1e9)
		ua.create_mapper = process_mapper_args(ua.create_mapper, blocksize)
	return ua





def _tester():
	ua = get_args(testing=True)
	easy_args.show_args(ua)


if __name__ == "__main__":
	_tester()
