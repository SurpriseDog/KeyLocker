#!/usr/bin/python3
# Functions for interacting with system utilities.
# Linux only for now, eventually this could split into linux.py and windows.py

import os
import re
import sys
import bitfun
import secrets
import subprocess

import psutil

from shared import rfs
from crypto import get_random
from sd.common import get_blocksize, error, query, warn, mrfs

def run(*args, encoding='utf-8', check=True, errors='replace', **kargs):
	"Quick run with strict checking"
	ret = subprocess.run(args, check=check, stdout=subprocess.PIPE, **kargs)
	return ret.stdout.decode(encoding=encoding, errors=errors).splitlines() if ret.stdout else []


def get_partitions():
	"Get a list of partitions and drives without partitions"
	majors = []
	devs = dict()
	with open("/proc/partitions") as f:
		lines = f.read()
		for line in reversed(lines.split('\n')):
			line = line.strip()
			if line.startswith('major'):
				break
			if line:
				major, minor, blocks, name = re.split('  *', line)

				# Ignore drives if partitions already listed
				if minor == '0' and major in majors:
					continue

				# Ignore fake drives
				if name.startswith('dm-') or name.startswith('loop'):
					continue

				majors.append(major)
				devs[name] = int(blocks) * 1024
	return devs


def start_end(dev):
	"Return the start and end byte of a device"

	def read(filename):
		with open(filename, 'r') as f:
			return f.read().strip()

	dev = dev.lstrip('/dev')
	partnum = read(os.path.join('/sys/class/block', dev, 'partition'))
	parent = dev.rstrip(partnum)
	dev = os.path.join(parent, dev)
	#print(dev, parent, partnum)
	start = int(read(os.path.join('/sys/block', dev, 'start'))) * 512
	size = int(read(os.path.join('/sys/block', dev, 'size'))) * 512
	return start, start + size


def get_serial(devname, verbose=0):
	"Get the serial number of a device"
	output = ''
	# print("Getting serial for", devname)
	for line in run(*"udevadm info --query=all --name".split(), devname):
		line = re.sub('.: ', '', line)
		if re.match('ID_SERIAL=', line):
			output += re.sub(".*ID_SERIAL=", '', line).strip()
	if verbose:
		if output:
			print("Found serial for device:", devname, '=', output)
		else:
			print("No serial number found for", devname)
	if not output:
		# This will be hashed ensuring that passwords for devices without serials don't interfere with text storage.
		return 'NO SERIAL FOUND FOR DEVICE'
	return output


def installed_gigs():
	"Get the installed (not just available) system memory in whole GiB"
	total = psutil.virtual_memory().total / 1024**3
	if total > 2.5:
		#Estimate:
		#https://unix.stackexchange.com/questions/426188/wrong-total-memory-in-vm
		return int(round(total + 0.3, 0))
	else:
		return int(total)


def show_mem():
	"Show memory installed"
	print("Free Mem:", mrfs(psutil.virtual_memory().available), 'of',
	      mrfs(psutil.virtual_memory().total), "total in userspace")

def mem_total():
	"Return total memory usable, some is reserved by system."
	return psutil.virtual_memory().total

def mem_avail():
	return psutil.virtual_memory().available


def get_table(devname):
	"Retrieve dmstep table for packing by bitfun"
	return run(*"dmsetup table --showkeys".split(), devname)[0]


def set_table(table, mapper_name=None):
	# print("dmsetup create", mapper_name, 'stdin:', ' '.join(table))
	run("dmsetup", "create", mapper_name, input=' '.join(table).encode())



def create_mapper(devname, offset, size, mapper_name):
	'''Create a new cryptsetup mapping
	Create a new device mapper:
	devname = device name to use
	offset = start in 512 byte blocks
	size = size in 512 byte blocks
	'''


	#Fix the mapper name
	while True:
		while not mapper_name:
			mapper_name = input("Type a name for the new /dev/mapper: ").strip()

		if os.path.exists(mapper_name):
			warn("Name already exists!")
			mapper_name = None
			continue
		else:
			print("Using mapper name:", mapper_name)
			break


	# Determine Device size
	if 'dev' in devname and os.path.exists(devname):
		blocksize = get_blocksize(devname)
	else:
		error(devname, "is not a valid device name")


	# Cryptsetup replaced with dmsetup so we can have multiple mappings on the same dev
	if not size:
		size = blocksize // 512 - offset

	'''
	Format: 0 <sector count> crypt <sector format> <key> <IV offset> <device> <sector offset>
	0 = Logical sector start (not physical on disk) = 0
	<sector format> is the encryption type like: aes-cbc-essiv:sha256
	<key> is replaced with the hexadecimal key randomly generated for stdin
	<IV offset> should be 0 except in special cases.
	<device>    is the physical device using /dev/... or Major:Minor number
	<sector offset> is the physical offset on the disk
	'''
	warn("Ready to create a mapper on", rfs(blocksize), devname)
	warn("From sector", offset, "to sector", offset + size, '=', rfs(size * 512))
	print("Data on", devname, "will be DESTROYED, not encrypted.")

	if query():
		run('dmsetup', 'create', mapper_name,
		    input=' '.join(['0', str(size), 'crypt', 'aes-cbc-essiv:sha256', '']).encode() + \
	        	  get_random(256 // 8).hex().encode() + \
	              ' '.join(['', '0', devname, str(offset)]).encode())

		print('\nDone!', '\n'.join(run('cryptsetup', 'status', mapper_name)), '\n')
		return mapper_name
	else:
		return False


def linear_mapper(dev, offset, end):
	'''Like create_mapper but without the encryption and warnings
	which is not needed as the KeyFile is already encrypted.
	All sizes are in 512 byte sectors
	'''
	# Future: This could be replaced by just writing to the correct sectors on the disk directly
	name = 'kltmp.' + secrets.token_urlsafe(8)
	table = ' '.join(['0', str(end - offset), 'linear', dev, str(offset)]).encode()
	run('dmsetup', 'create', name, input=table)
	return os.path.join('/dev/mapper', name)


def open_slack(dev, start, end, sector=512):
	"Open slack space in drive, Future: Check for overlaps with existing data"
	mapper = bitfun.FileMapper(dev, (start * sector, end * sector))

	#Overwrite any blank sections, ask if existing data found
	clean = 0
	dirty = 0
	zero = b'\x00'* sector
	while True:
		data = mapper.read(sector)
		if not data:
			return mapper
		if data == zero:
			mapper.seek(-sector, 1)
			mapper.write(get_random(sector))
			clean += 1
		if len(data) == sector and data != zero:
			# Check if previous sectors were clean but this one is dirty
			if dirty == 0 and clean > 0:
				warn("Found existing data in slack, overwrite?")
				if not query():
					mapper.close()
					sys.exit(1)
				dirty += 1


def mkfs(mapper, filesystem='ext4'):
	# Create a filesystem on the mapper.
	# This prevents weird errors where the installer will try to make a partition within the mapper
	if not query('Make', filesystem, 'filesystem on', mapper + '?'):
		return False
	while True:
		if not query('Using type:', filesystem + '?'):
			filesystem = input('Input filesystem type: ')
		try:
			run("mkfs", "-t", filesystem, os.path.join('/dev/mapper', mapper))
			return True
		except:
			print("Error making filesystem! Type ctrl-c to exit.")




def get_mapper_name(mapper_name):
	for line in run("cryptsetup status".split(), mapper_name):
		if ' device:' in line:
			devname = re.sub(' *device: *', '', line)
			break
	else:
		error("Could not find device", devname, '''in cryptsetup status.
		To create a new device mapper run again with --create''')
	return devname


def sector_scanner(dev, start=0, end=0, sector=512, printme=True):
	'''
	Read sectors and return True if populated
	start and end are in sectors
	'''
	dirty = False
	zero = b'\x00'*sector
#
	def iprint(*args, **kargs):
		if printme:
			print(*args, **kargs)
#
	with open(dev, 'rb') as f:
		f.seek(start*sector)
		pos = f.tell() // sector
		count = 0
		column = max(len(str(end // sector)) + 1, 4)
#
		while pos < end or not end:
			if not count % 64:
				iprint("\n", str(pos).rjust(column), ' ', end='')
			data = f.read(sector)
			if data == zero or not any(b for b in data):
				iprint('_', end='')
			else:
				dirty = True
				iprint('X', end='')
			tell = f.tell() // sector
			if tell == pos:
				iprint()
				# warn("Premature stream end")
				break
			else:
				pos = tell
				count += 1
		iprint('\n')
		return dirty


def junk_dir(directory, size=1024**2, max_t=6):
	'''
	Fill a directory with junk files, sync and then delete them
	size    = size of junk files
	max_t   = Stop after this amount of time. 0 = Unlimited
	'''
	if not os.access(directory, os.W_OK):
		warn("Cannot write data to", directory)
		return

	start = time.time()
	junkfiles = set()
	# Write out junk file to the correct directory
	while True:
		try:
			filename = os.path.join(directory, 'junkfile.' + str(randint(0, 2**64)))
			with open(filename, 'wb') as j:
				junkfiles.add(filename)
				j.write(os.urandom(size))
				j.flush()
				os.fsync(j)
		except IOError:
			# Break if can't write or filesystem full
			break
		if max_t and time.time() - start > max_t:
			break

	# Delete them.
	for name in junkfiles:
		os.remove(name)
