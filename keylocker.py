#!/usr/bin/python3
# Run with -h to see options.
import sys
sys.dont_write_bytecode = True	# pylint: disable=C0413

import os
import re
import gc
import time
import signal
import random
import importlib.util
from functools import partial

import shared
import system
import crypto
import text_editor
import bitfun as bf
from args import get_args
from slots import KeyLocker
from sd.hash_mouse import HashMouse
from sd.common import uerror as error, mrfs, undent, warn
from sd.common import list_get, query, doter, spawn, ConvertDataSize, randint, strip_punct

CDS = ConvertDataSize(binary_prefix=shared.BINARY_PREFIX, rounding=4096)

def create_salt(args):
	"Create salt files: <directory> <count> <size> <name>"
	directory = args(create_salt, 0, '.')
	count = int(list_get(args, 1, 1))
	size = CDS(list_get(args, 2, 0))
	input_name = list_get(args, 3, '')
	if size < 1e6:
		size = 10e6 * random.SystemRandom().random()

	if not os.path.exists(directory):
		error("Directory:", directory, "does not exist")
	if not os.access(directory, os.W_OK):
		error("Cannot write to", directory)

	for x in range(count):
		name = input_name or 'random'
		filename = os.path.join(directory, str(x + 1) + '.' + name)
		if os.path.exists(filename):
			filename += '.' + str(int(time.time()))
		crypto.create_random_file(filename, size * .9, size * 1.1)
		yield filename


def set_phash(datafile, verify=True):
	# Ask for a password and set the argon2 hash in the datafile
	passlen = 0 if UA.devmode else 8
	phash = crypto.run_argon(\
							 key=crypto.read_pass(minimum=passlen,
							 					  verify=verify,
							 					  insecure=UA.insecure_pass),
							 salt=datafile.salt.digest(),
							 rounds=UA.hash_rounds,
							 mem=UA.hash_mem,
							 threads=UA.hash_threads)
	datafile.set_phash(phash)



def read_datafile(datafile):
	"Read the datafile and return data if correct password is provided"
	tri = 0
	while True:
		tri += 1
		set_phash(datafile, verify=False)
		data = datafile.read_slot()
		if data:
			break
		print("Try", tri, "- Password incorrect or data slot does not exist\n")
		if tri <= UA.password_tries:
			time.sleep(1.2**tri)
		else:
			#Wipe on max tries, Example: if 3, it will wipe on 4th try if incorrect (to avoid any confusion)
			if UA.wipe_on_max_tries:
				datafile.wipe()
			break
	if data:
		return data
	else:
		error("Too many password tries... Goodbye!")
		return None


def create_datafile(filename):
	"Create a datafile"
	print("\nCreate new datafile:", UA.datafile_name)
	if not query('Yes or No?'):
		return False
	while True:
		uin = input("Input size or press enter for a random size: ")
		if not uin:
			size = randint(2e6, 5e6)
			break
		size = CDS(uin)
		if size:
			break

	# Warning if slot area is too small:
	if size < 0.02e6 and not UA.batch_mode:
		warn(undent('''
		Using tiny file sizes can result in loss of data with multiple keys.
		If you understand the risk and wish to continue, type: GOODBYE
		beacuse that is what you will be saying to your keys if you continue.'''))
		if not query("What will you be saying to your multiple keys if you continue? (Type QUIT to cancel)",
					 confirmation='GOODBYE', negation='QUIT'):
			return False

	crypto.create_random_file(filename, size * 0.98, size * 1.02)
	return True


def openfile(filename):
	# Create the datafile in write mode if it doesn't exist
	if not os.path.exists(filename):
		if UA.mode == 'read':
			error("No datafile found at:", filename, 'and cannot create one in read mode')
			return False
		else:
			if not create_datafile(filename):
				return False


	# Check access
	"Open the datafile or section on disk"
	if not os.access(filename, os.R_OK):
		error("Can not access:", filename)

	canwrite = os.access(filename, os.W_OK)
	if UA.mode == 'write' and not canwrite:
		error("Can not write to:", filename)

	if filename.startswith('/dev') and UA.mode == 'read':
		safety_check()
		warn("Are you sure you want to put the datafile in the free space of the MBR?")
		warn("This is untested and will cause data destruction on GPT disks")
		if not query():
			return False
		file = system.open_slack(filename)
	else:
		if canwrite:
			file = open(filename, 'r+b')
		else:
			file = open(filename, 'rb')

	return file

###############################################################################


def safety_check():
	if UA.devmode:
		return
	warn("Directly editing partitions is a great way to accidentally destroy data.")
	warn("Make a FULL BACKUP OF THE ENTIRE COMPUTER before continuing.")
	print("Better yet, practice the commands in a virtual machine until you verify they do what you think they do.")
	check = input('Type: "I made a backup" to continue: ')
	if strip_punct(check.lower().strip()).replace(' ', '') != 'imadeabackup':
		# You Betta Back It Up!
		error("User did not back it up")


def alpha_warn():
	"Warning to alpha users"
	if UA.devmode:
		return
	warn("ALPHA SOFTWARE:")
	with open('ALPHA_WARNING.TXT') as f:
		for line in f.readlines():
			print(line, end='')

def main(salt):
	"Main Program"
	datafile_name = UA.datafile_name    # Filename
	devname = UA.devname                # Device Name
	mapper_name = UA.mapper_name        # /dev/mapper/name???
	data = None


	if devname:
		salt.update(system.get_serial(devname).encode())
		warn("Hashing", devname)
	file = openfile(datafile_name)
	if not file:
		return False

	datafile = KeyLocker(file, seed=salt.digest(), batch_mode=UA.batch_mode)
	salt.update(os.urandom(4096))
	print("\n")


	# Get a key from an existing slot:
	if UA.mode == 'read':
		if devname:
			print("Ready to read code from datafile for device:", devname)
			safety_check()
			data = bytearray(read_datafile(datafile))
			typ, part_num = bf.get_format_byte(data.pop(-1))
			if typ != 'dm':
				error("Data found in slot is:", typ, 'not', 'device-mapper format')
			devname = re.sub("[0-9]*$", '', devname) + (str(part_num) if part_num else '')
			table = bf.unpack_table(data)
			table.insert(6, devname)

			if devname:
				print("Slot data recovered. Unlocking device on", devname)
			if UA.print_table:
				print(table)
			if not mapper_name:
				mapper_name = input("Type /dev/mapper name to use: ")
			system.set_table(table, mapper_name)

		else:
			data = read_datafile(datafile)
			crypto.show_text(data)


	# Write a key into a new slot
	if UA.mode == 'write':
		if shared.MOUSE_HASHER:
			shared.MOUSE_HASHER.ensure_min()
		set_phash(datafile)

		if mapper_name:
			print("Ready to write code from", mapper_name, "into datafile:")
			datafile.write_slot(bf.pack_table(system.get_table(mapper_name)) + bf.make_format_byte(mapper_name))
		else:
			data = bytearray(KeyLocker.max_data)
			length = crypto.enter_password(data, prompt='Input text to write into datafile:')
			datafile.write_slot(data[:length])

	#Cleanup
	bf.wipe_bytes(data)
	datafile.close()
	return True

def start_mouse():
	"Start the mouse hasher if possible"
	if not os.environ.get('DISPLAY') or UA.batch_mode or UA.disable_mouse:
		return False
	if shared.MOUSE_HASHER:
		return True

	if not importlib.util.find_spec('Xlib'):
		warn("Xlib not installed")
		print("Run: sudo python3 -m pip install Xlib")
		print("To get mouse hashing functionality\n")
		return False

	mouse = HashMouse()
	if mouse.active:
		shared.MOUSE_HASHER = mouse
		signal.signal(signal.SIGTERM, exit)
		return True
	else:
		print("Could not hash mouse, falling back on default")
		return False


def goodbye(code=0):
	if shared.MOUSE_HASHER:
		shared.MOUSE_HASHER.quit()
	sys.exit(code)


def check_status():
	"Check that everything is okay"

	# Verify that everything is okay
	if not UA.datafile_name:
		error("You must specify a datafile name")

	# Check enough memory is available
	if system.mem_total() * 0.99 < UA.hash_mem:
		error("Not enough memory!", mrfs(system.mem_total()), 'available vs', mrfs(UA.hash_mem), 'requested')

	# https://superuser.com/q/1115983/1023751
	if system.mem_avail() * 0.99 < UA.hash_mem:
		warn("Low memory:", mrfs(system.mem_avail()), 'available vs', mrfs(UA.hash_mem), 'requested')
		warn("Make sure your swap space is setup properly to continue. Some systems may crash if the OOM killer does not do it's job properly. Try decreasing the memory requirement with --mem or installing more ram in your computer.")	# pylint: disable=C0301
		if not query("Continue?"):
			return False
	return True

def show_status():
	"Show info before continuing and verify"
	#Show basic info and verify that everything is okay
	# List available partitions
	if not UA.batch_mode:
		print("\nAvailable Partitions:")
		for name, size in sorted(system.get_partitions().items()):
			print('{0:11s}'.format('/dev/' + name), shared.rfs(size))


	print("\nProgram Mode :", end=' ')
	if UA.devname:
		if UA.mode == 'write':
			print("Write device keys to datafile.")
		else:
			print("Read device keys from datafile and modify system mapper table.")
	else:
		if UA.mode == 'write':
			print("Write text to datafile")
		else:
			print("Read text from datafile")


	print("Datafile Name:", UA.datafile_name)

	if UA.mapper_name and UA.mapper_name != UA.devname:
		print("Device Name  :", UA.mapper_name, 'on', UA.devname)
	else:
		print("Device Name  :", UA.devname)

	print("Salt Files   :", UA.salt_files if UA.salt_files else '')
	system.show_mem()
	return True


def setup():
	"Run setup tasks"

	# Start hashing files early
	que, thread = spawn(crypto.hash_files, UA.salt_files, megs=64)

	# Create salt files, if requested
	if UA.create_salt_list:
		create_salt(UA.create_salt_list)
		goodbye(0)

	# Create a brand new devmapper
	if UA.create_mapper:
		safety_check()
		offset, size = UA.create_mapper
		mapper = system.create_mapper(UA.devname, offset, size, UA.mapper_name)
		if mapper:
			UA.mapper_name = mapper
		else:
			goodbye(0)

		# Create filesystem:
		time.sleep(1)
		system.mkfs(mapper)

	if not check_status():
		return False
	show_status()
	if not UA.batch_mode and not query("\nIs this correct?"):
		return 'redo'

	#Wait for salt digest to finish calculating
	doter(thread.is_alive, header='Hashing')
	salt = que.get()
	return salt


if __name__ == "__main__":
	os.nice(5)				# Ensure the OOM killer takes this first
	while True:
		UA = get_args()		# User arguments
		start_mouse()		# Start the mouse hasher early
		alpha_warn()
		if UA.devmode:
			warn = partial(warn, delay=0)
		SALT = setup()
		if SALT == 'redo':
			print("Okay, you can edit keylocker options below. Press ctrl-c to quit:")
			sys.argv = text_editor.text_editor(' '.join(sys.argv)).split()
			continue
		main(SALT)
		gc.collect()
		goodbye()
