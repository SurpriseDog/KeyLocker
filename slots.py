#!/usr/bin/python3

import os
import io
import sys
import time
import secrets
from hashlib import sha512

import shamir
from shared import rfs, rand, TERM_WIDTH
from bitfun import ByteTracker, to_bytes, from_bytes, log, wipe_bytes, ABA
from crypto import run_argon, get_prime, get_random, decrypt_data, encrypt_data

from sd.common import sround, randexp, plural, fmt_time, error, rns
from sd.common import roundint, percent, warn, randint, DotDict, chunker, undent


class KeyLocker:
	'''
		Write a small amount of data to encrypted shamir slots in a file
		Useful for locking up keys. A sort of "Key Locker" if you will.
		Datafile format:
		<salt_len> <.....num_slots * 64......><.......optional data portion......><salt_len>

	'''

	slot_len = 64
	'''Bytes per slot (overruns allowed in normal mode)
	"64.0B ought to be enough for anybody"
	This allows 256 bit keys, but creates a problem when encoding 512 bit xts mode,
	which is why double sized slots are allowed.
	'''

	max_len = 256				# Maximum slot length, any larger will break ABA
	max_shamir = slot_len * 2
	'''Maximum shamir slot length
	Works pretty fast up to 256 bytes then slows down so a larger slot size is easily doable.
	Ultimately it's the get_prime function which slows everything down so that could be
	multiprocessed for larger slot sizes.
	Bytes   Time:
	64      0.07
	128     0.16
	256     0.11
	512     2.88
	1024    7.50
	2048    Gave up waiting
	Interesting fact: 392 bytes takes 3.6 times longer to run than 391 bytes.
	It just gets worse from there on out.

	Future: Store a 64 byte shamir share with this inside:
	key = bytearray(get_random(32))
	ABA(b'Long Shamir' + key + to_bytes(length), size=54, seed=b'Long Shamir')
	Where key is 192 random bits that goes through argon (in easy mode):
	crypto.run_argon(key, b'SALTSALT', 3, -3, 16, verbose=0)
	to make a new phash which is then used to open
	shamir shares of a size given by the 2 byte length.
	then send the given length to a parameter in read_slot and write_shamir
	'''

	# Maximum data size supported by KeyLocker
	max_data = 255 - ABA.header

	# Size of the first salt + slots, Should align with 4096 sector boundaries
	max_area = 1024 * 1024

	def __init__(self, file, phash=None, seed=b"", shamir_mode=True, batch_mode=False, testing=False):
		self.phash = phash              # A long hash to pull a key, iv and more from
		self.file = file                # File Handle
		self.shamir_mode = shamir_mode  # Use multiple shamir slots instead of just duplicating data
		self.powtwo = False             # Show numbers in power of two form
		self.testing = testing			# Testing mode
		self.graphics = True            # Show the blinking dots
		self.batch_mode = batch_mode    # No warnings, No delays
		self.set_boundaries()			# Set boundaries for slot area
		self.salt = self.calc_salt(seed)
		if phash:
			self.set_phash(phash)

	def calc_salt(self, seed):
		# Get Salt from any salt files then from header and footer of datafile
		self.file.seek(0)
		salt = sha512()               # Salt hasher
		salt.update(self.file.read(self.salt_len))
		self.file.seek(-self.salt_len, 2)
		salt.update(self.file.read(self.salt_len))
		salt.update(seed)
		return salt

	def set_boundaries(self):
		"Determine area boundaries, (the portion with the actual slots) and calculate number of slots"

		# Calculate area size for slot storage
		filesize = get_size(self.file)
		self.salt_len = self.calc_salt_size(filesize)
		notsalt = filesize - self.salt_len * 2
		if notsalt >= self.max_area * 2:
			self.area = self.max_area
		elif notsalt >= self.max_area // 5:
			self.area = notsalt // 2
		else:
			self.area = notsalt
			if self.shamir_mode:
				print("File size too small, disabling Shamir mode")
				self.shamir_mode = False

		# Calculate the file storage area
		self.storage = filesize - self.salt_len * 2 - self.area

		# Number of slots must fit entirely within area, even with long slots
		self.num_slots = (self.area - self.max_len) // self.slot_len

		#Sanity check
		if not self.testing:
			self.show_size()
		if filesize != self.salt_len * 2 + self.area + self.storage:
			error("Miscalculation for Datafile")
		if self.num_slots < 10:
			error("Not enough slots available")
		if self.num_slots * self.slot_len + (self.max_len - self.slot_len) > self.area:
			error("Slot area miscalculation:",
			      self.num_slots * self.slot_len + (self.max_len - self.slot_len), self.area)

		# Slot target: (numbers are approximate, see the get_slot_count function)
		if self.area >= 1024 * 1024:
			self.slot_target = 4
		else:
			self.slot_target = 8

		# Maximum possible number of slots for target number
		self.slot_max = self.slot_target * 2 + 1

		# Number of shamir slots
		self.slot_max = self.slot_max

		# If shamir required slots to unlock is too big it causes slowdowns and corruption
		self.max_reqs = 4

	def set_phash(self, phash):
		"set the phash and track sections of the phash with ByteTracker"
		self.phash = phash
		tracker = ByteTracker(len(self.phash), self.slot_max+1)
		self.tracker = DotDict()

		self.tracker.shamir_key = tracker.reserve(32, 1)[0]
		self.tracker.key = tracker.reserve(32)

		self.tracker.shamir_vector = tracker.reserve(16, 1)[0]
		self.tracker.vector = tracker.reserve(16)

		self.tracker.prime = tracker.reserve(64 + 128, 1)[0]
		self.tracker.offset = tracker.reserve(16)
		# dprint('last byte', self.tracker.offset[-1].stop)

	@staticmethod
	def calc_salt_size(size):
		'''self.salt_len is the length of salt on each side of the file.
		Integer divison only here because there cannot be any floating point errors.
		Biased towards larger % salt with smaller files.
		Total = self.salt_len * 2'''
		divisor = 8 * len(str(size))
		salt = size // divisor

		# Limit to avoid wasting space and waiting for big files.
		# Also bigger salt_len are susceptible to sector errors
		# On this ultrabook, Sha512.update() takes about 50ms to read 20MiB
		salt_max = 10 * 1024 * 1024
		if salt > salt_max:
			salt = salt_max

		# Make data align with sector boundries:
		if salt > 4096 * 4:
			return roundint(salt, 4096)
		else:
			return salt


	def show_size(self):
		"Print a graphical repation of the file"

		filesize = get_size(self.file)
		salt = self.salt_len
		area = self.area
		storage = self.storage
		margin = ' ' * 4
		width = TERM_WIDTH - len(margin) * 2

		def rep(obj, label, spacer='.'):
			"return <...LABEL..> sized appropriately"
			out = '<' + label.title() + '>'
			wanted = int((obj / filesize) * width)
			if len(out) < wanted:
				dots = (wanted - len(out)) // 2
				return '<' + spacer * dots + label.title() + spacer * dots + '>'
			return out

		out = [margin,
			   rep(salt, 'salt ' + percent(salt / filesize)),
			   rep(area, 'slots ' + percent(area / filesize)),
			   rep(storage, 'storage ' + percent(storage / filesize)),
			   rep(salt, 'salt ' + percent(salt / filesize)),
			   margin, ]

		if not self.storage:
			out.pop(-3)


		def trim():
			"Trim any excess dots"
			while '.' in ''.join(out):
				for index, _val in enumerate(out):
					excess = sum([len(item) for item in out]) - width
					if excess > 0:
						excess //= 2
						out[index] = out[index].replace('.', '', 1)
						out[index] = out[index][::-1].replace('.', '', 1)[::-1]
					else:
						return

		trim()
		if self.num_slots > 9999:
			print("\nSpace for:", rns(self.num_slots), 'slots in', rfs(self.area) + ':')
		print("Salt Length:", rfs(self.salt_len), '=', self.salt_len)
		print("Slot Area:", rfs(self.area), '=', self.area)
		if self.storage:
			print("Storage Length:", rfs(self.storage))
			ss = self.salt_len + self.area		#storage start
			print("Storage start byte:", ss, "offset", ss % 4096)
		print(''.join(out), '\n')

	def get_key(self, seg):
		if seg == 'shamir':
			#Shamir key
			return self.phash[self.tracker.shamir_key], self.phash[self.tracker.shamir_vector]
		else:
			return self.phash[self.tracker.key[seg]], self.phash[self.tracker.vector[seg]]

	def get_prime(self, data_len):
		prime = get_prime(data_len, bytes(self.phash[self.tracker.prime]))
		# print('Prime', log(prime))
		return prime

	def get_offset(self, seg):
		"Get a 128 bit pseudorandom number:"
		# Validate that phash is not exhausted:
		assert self.tracker.offset[seg].stop < len(self.phash)

		big = from_bytes(self.phash[self.tracker.offset[seg]])
		# print('Offset', log(big % self.num_slots * self.slot_len + self.salt_len))
		return (big % self.num_slots) * self.slot_len + self.salt_len

	def close(self):
		"Close the file and wipe phash bytes"
		self.salt.update(os.urandom(4096))
		self.file.flush()
		self.file.close()
		wipe_bytes(self.phash)

	def get_slot_count(self, target, sigma=0.5):
		'''Use the log normal function to choose how many slots to generate.
		The goal is to be likely, but not guaranteed to use many slots.
		https://en.wikipedia.org/wiki/Log-normal_distribution
		Should center around target
		Guaranteed to be at least 1'''

		# Bias towards the target value
		if rand.random() < .2:
			return target

		# Keep a small baseline of any value for larger targets
		if target > 6 and rand.random() < .1:
			return randint(1, self.slot_max - 1)

		# The log normal distribution with it's lonq right hand tail
		value = (rand.lognormvariate(0, sigma) * 1) * target

		# Bias away from small values
		if value < target:
			value *= 3

		# Values over slot_max produce array lookup errors
		if value > self.slot_max:
			return self.get_slot_count(target)

		# Writing zero slots means no data.
		if value < 1:
			return 1

		return int(value)

	def show_offsets(self, slots, rate=1 / 10, reps=1):
		"Show the blinking dots on slot creation"
		if not self.graphics or self.batch_mode:
			return

		margin = ' ' * 4
		width = TERM_WIDTH - 2 - len(margin) * 2
		space = self.num_slots * self.slot_len

		# List of characters to blink with:
		# blink = "😞😐😏😃😌"
		# blink = "😞😐😃"
		# width -= 6
		# empty = "◌"

		# blink = "○◔◑◕●"
		blink = "○●"
		empty = '-'

		stars = [0] * width
		for offset in slots:
			pos = int((offset - self.salt_len) / space * width)
			stars[pos] += 1
		for x, _val in enumerate(stars):
			c = stars[x]
			if c == 0:
				stars[x] = empty
			elif c == 1:
				stars[x] = blink[-1]
			else:
				stars[x] = str(c)

		for x in range(reps):
			for c in blink:
				stars[pos] = c
				sys.stderr.write('\r' * width + margin + '|' + ''.join(stars) + '|')
				sys.stderr.flush()
				time.sleep(rate)
		time.sleep(0.2)

	def write_slot(self, data):
		"Write data to slots"
		if self.shamir_mode and len(data) + ABA.header >= self.max_shamir:
			print("Shamir mode is limited to:", self.max_shamir)
			print("Reverting to normal mode.")
			self.shamir_mode = False

		if self.shamir_mode:
			data = ABA(encrypt_data(data, *self.get_key('shamir')), size=self.slot_len)
		else:
			data = ABA(data, size=self.slot_len)
		data.scramble()

		# Fill out slots with random data just in case a previous run used the same password:
		print("Checking for previous data in this slot...")
		if self.testing or self.read_slot():
			print("\nFound previous data in this slot with the same password, overwriting...")
			for seg in range(self.slot_max):
				offset = self.get_offset(seg)
				self.file.seek(offset)
				self.file.write(get_random(self.slot_len))
			else:
				print("Done")

		if self.shamir_mode:
			self.write_shamir(data)
		else:
			self.write_normal(data)
		print()

		# Verify data slot can actually be retrieved
		self.file.flush()
		ret = bytearray(self.read_slot())
		if ret:
			print("Slot data verified.")
		else:
			error("Failed to verify data!")

	def get_valid_slots(self, minimum, maximum, data_len):
		"Return list with valid slots"

		def test_offsets(offsets):
			"Test offsets for overlaps or being too close to each other"
			for low, high in chunker(offsets, overlap=True):
				if high - low < data_len:
					return False
			return True

		for tri in range(1, int(1e5)):
			valid_count = min(maximum, self.get_slot_count(self.slot_target) - 1 + minimum)
			valid = [1] * valid_count + [0] * (maximum - valid_count)
			rand.shuffle(valid)

			offsets = sorted([self.get_offset(index) for index, val in enumerate(valid) if val])
			if test_offsets(offsets):
				break
			if not tri % 10000:
				print(rns(tri), 'slot tries')

		else:
			error('''Cannot find a valid slot configuration for file.
					 Try increasing the file size or using a different password.''')


		# dprint("Valid Slots:", valid, minimum, valid_count, maximum)
		# dprint(offsets)
		return valid


	def write_shamir(self, data):
		'''Shamir Mode:
		Break up the data into a number of "shares" that must be reconstituted together
		with a minimum number to reconstruct data'''

		#Add bytes to make sure prime is big enough.
		if not data.end % 64:
			data.arr += b'0'*64
			data.prepend()

		data_len = len(data.arr)
		prime = self.get_prime(data_len)

		# Append random data on end of data while keeping value below that of prime
		for tri in range(1, int(1e5)):
			junk = get_random(self.slot_len*2)
			data.scramble(junk)
			if from_bytes(data.arr) >= prime:
				if not tri % 10000:
					#It doesn't matter how many tries, if it's not found in first 10k
					print("Prime attitude adjustment #", rns(tri))
			else:
				break
		else:
			error("Could not pad data properly to be less than prime ¯\\_(ツ)_/¯")


		# Minimum number of shares   2 - 4
		minimum = min(self.get_slot_count(self.slot_target) + 1, self.max_reqs,
					  self.slot_max - self.slot_target)

		# Number of valid shares
		valid = self.get_valid_slots(minimum, self.slot_max, len(data.arr))


		#Info:
		print("\nWriting", sum(valid), "Shamir shares of which", minimum, "are needed to reconstruct code:")
		if self.powtwo:
			print("Prime:", sround(log(prime), 3))
			print("Data:", sround(log(data), 3))
			print('min =', minimum, 'valid', valid, 'self.slot_max', self.slot_max,
				  'extra:', sum(valid) - minimum)

		#Write shares indexes that are valid
		offsets = []
		for index, share in enumerate(shamir.make_shares(minimum, self.slot_max, prime, data.arr, data_len)):
			if valid[index]:
				if self.powtwo:
					print(sround(log(share)))
				offset = self.get_offset(index)
				offsets.append(offset)
				self.file.seek(offset)
				self.file.write(encrypt_data(share, *self.get_key(index)))

		#Cleanup
		rand.shuffle(valid)
		self.show_offsets(offsets)


	def write_normal(self, data):
		'''Normal mode: Write encrypted data to each slot and check if valid
			Randomly choose a password segment from those given by the password hash and
			use that data to choose an encryption key and an offset for the data.'''
		slots = [1] * self.get_slot_count(self.slot_target) + [0] * self.slot_max
		slots = slots[:self.slot_max]
		# dprint(slots)
		rand.shuffle(slots)

		offsets = []
		for seg, val in enumerate(slots):
			if val:
				offset = self.get_offset(seg)
				offsets.append(offset)
				self.file.seek(offset)
				self.file.write(encrypt_data(bytes(data.arr), *self.get_key(seg)))
		self.show_offsets(offsets)


	def read_slot(self):
		'''
		Read a data slot and return the data (if correct password) for a given device.
		Returns bytearray
		'''

		# Go through each password segment for one that might decrypt the data.
		# Assuming non-shamir mode first.
		print("Attempting to decrypt data...")
		found_count = 0
		for seg in rand.sample(range(self.slot_max), self.slot_max):
			offset = self.get_offset(seg)
			self.file.seek(offset)
			data = ABA(decrypt_data(self.file.read(self.max_len), *self.get_key(seg)), raw=True)
			if data.validate():
				found_count += 1
				if found_count == 1:
					valid = data
				else:
					data.destroy()
				if found_count >= 2:
					break

		if found_count > 0:
			if found_count == 1 and not self.testing:
				warn(undent('''No spare slots dectected for data.
				It's recommended that you rerun the program in write mode to generate more.'''))
			ret = bytearray(bytes(valid))
			valid.destroy()
			return ret

		# Try to recover shamir shares
		datablock = [None] * self.slot_max			#Encrypted shares from file
		for seg in range(self.slot_max):
			offset = self.get_offset(seg)
			self.file.seek(offset)
			raw = self.file.read(self.max_shamir)
			datablock[seg] = bytearray(decrypt_data(raw, *self.get_key(seg)))

		for data_len in (self.slot_len, self.slot_len * 2):
			print("\nTrying to recover", data_len, "byte blocks")
			prime = self.get_prime(data_len)
			data = self.read_shamir(prime, [from_bytes(share[:data_len]) for share in datablock])
			if data:
				#Cleanup and run bogus data through read_shamir
				for block in datablock:
					wipe_bytes(block)
				for _x in range(99):
					self.read_shamir(prime,
					                 [from_bytes(os.urandom(data_len)) for share in datablock], giveup=99)
				return bytearray(decrypt_data(bytes(data), *self.get_key('shamir'), crop=len(data)))
		return bytearray()


	def read_shamir(self, prime, shares, giveup=0):
		'''
		Try different combos to recover shamir share
		Fast enough there's no need for multithreading
		'''
		valid = None						# A validated result
		start_time = time.perf_counter()
		backup = False						# Valid and backup found
		share_c = len(shares)
		tries = 0

		for tries, combo in enumerate(shamir.get_combos(share_c, maximum=self.max_reqs)):
			# Recover the shares with shamir.py
			result = ABA(to_bytes(shamir.interpolate(prime, combo, [shares[seg-1] for seg in combo])), raw=True)
			#Check the result and make sure there is a spare
			if result.validate():
				# print('found result', result)
				if not valid:
					valid = result
				else:
					backup = True
					result.destroy()
					print("Success after", plural(tries + 1, "try"), 'in',
					      fmt_time(time.perf_counter() - start_time))
					# dprint([x-1 for x in combo])
					break

			if giveup and tries >= giveup:
				return None

		if valid:
			if not backup and not self.testing:
				warn(undent('''
				Warning! No spare shamir shares found for this key.")
				Should even ONE of the existing shares be overwritten...
				then say goodbye to your data!
				'''))
				time.sleep(1)
				warn("It's recommended that you rewrite this key into the datafile!")
				time.sleep(1)
			return valid

		# No valid share found
		# dprint("Failure after", plural(tries + 1, "try"), 'in', fmt_time(time.perf_counter() - start_time))
		return None

	def wipe(self, reps=3):
		'''Destroy the data file. No guarantee of success on an SSD,
		but with the design of the data file, if we manage to corrupt
		even a few bytes in the SALT or key area, then the whole thing
		is rendered useless.
		'''
		if 'w' not in self.file.mode and '+' not in self.file.mode:
			warn("Cannot wipe file in read mode")
			return

		for _x in range(reps):

			# Using os.urandom to avoid mouse if it's not ready
			self.file.seek(0)
			self.file.write(os.urandom(self.salt_len + self.area))
			self.file.flush()

			# Erase trailing salt section
			self.file.seek(-self.salt_len, 2)
			self.file.write(os.urandom(self.salt_len))
			self.file.flush()

			# Sync
			os.fsync(self.file)

			time.sleep(0.1)
			print('.', end='', flush=True)


def get_size(file):
	"Get file size of open file handle"
	tell = file.tell()
	file.seek(0, 2)
	size = file.tell()
	file.seek(tell)
	return size


def quick(max_t=2):
	"Quick run through"
	start = time.time()
	while time.time() - start < max_t:
		exp = randint(10, 20)
		size = randint(2**exp, 2**(exp + 1))
		file = io.BytesIO(os.urandom(int(size)))
		phash = os.urandom(4096)
		ds = KeyLocker(file, phash, testing=True, batch_mode=True)
		text = secrets.token_bytes(randint(5, 105))
		ds.write_slot(text)



def _tester():
	while True:
		size = int(randexp(10, 22))
		print("\n"*4)
		password = secrets.token_urlsafe(18)
		file = io.BytesIO(os.urandom(int(size)))
		phash = run_argon(password, salt=os.urandom(8), rounds=1, mem=64*1024**2, threads=16)
		ds = KeyLocker(file, phash, testing=True)
		ds.graphics = False

		for counter in range(9):
			ds.shamir_mode = bool(randint(0, 1))
			text = secrets.token_bytes(randint(1, KeyLocker.max_data))
			#text = ("This is a very secret text" * 7).encode()

			if counter:
				del phash[:2]

			print("Secret length", len(text), 'bytes')
			ds.write_slot(text)
			result = ds.read_slot()

			if text != result:
				print(len(text), bytes(text))
				print(len(result), bytes(result))
				error("Verification Error!")
			print("\n\n")

		ds.close()

if __name__ == "__main__":
	_tester()
	#quick()
