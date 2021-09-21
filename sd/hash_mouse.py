#!/usr/bin/python3
# Spawn a new thread to constantly sample x, y, window id and timestamps for each mouse position
# and then returns a hash of this data on request
# Usage ./hash_mouse.py


import os
import sys
import time
import signal
from hashlib import sha512
import multiprocessing as mp

import Xlib
import Xlib.display
from Crypto.Cipher import AES

HASH_WIDTH = sys.hash_info.width


def hash8(data):
	'''
	Return an 8 byte qhash of data (only valid for each program run)
	Used to test for data integrity between threads.
	'''

	if HASH_WIDTH == 64:
		return hash(data).to_bytes(8, 'big', signed=True)
	else:
		return sha512(data).digest()[:8]


def watcher(shared, root, verbose=0, sleep_t=1/64, min_dots=64, slow_mode=False, seed='', extra_random=True):
	'''
	Function to watch mouse and update a hash. Called by HashMouse so it can run in background.
	root 			= root display
	min_dots        = minimum number of dots before slowing down sampling rate
	extra_data      = #Throw in extra random data just in case
	'''

	pos = ''
	count = 0  # Number of mouse positions sampled.
	history = [os.urandom(64).hex()] * 16  # History of mouse movements
	index = 0  # Pointer to the current place in array
	hasher = sha512(seed.encode('utf-8'))

	def update_hash():
		'''Update hasher with the data from history, save digest to shared'''

		hasher.update(' '.join(history[:index]).encode('utf-8'))
		if extra_random:
			hasher.update(os.urandom(64))

		d0 = count.to_bytes(8, 'big')
		d1 = hasher.digest()
		d2 = hash8(d0 + d1)
		dt = d0 + d1 + d2
		shared[:len(dt)] = dt

	signal.signal(signal.SIGTERM, exit)
	while True:
		data = root.query_pointer()
		new_pos = str((data.root_x, data.root_y)) + str(data.child)[-9:][:-1]
		if pos != new_pos:
			# Add the new mouse position to the histoy
			pos = new_pos
			history[index] = new_pos + ' '.join(
				(time.time().hex(), time.process_time().hex(), time.perf_counter().hex()))
			# print(history[index])
			count += 1
		else:
			time.sleep(sleep_t * 4)
			continue

		# When history array is maxed out, run it through the hash
		if index == len(history) - 1 or (count <= min_dots and index == 0):
			update_hash()
			index = 0
		else:
			index += 1

		# Write dots out to screen to show progress
		if verbose >= 2 and count > 0:
			sys.stderr.write('.')
			sys.stderr.flush()

		# Slow it down when min_dots is reached
		if slow_mode and count == min_dots:
			sleep_t *= 4

class HashMouse:
	'''Class to monitor watcher thread and return values on command.'''

	def __init__(self, verbose=0, min_dots=64, **kargs):
		self.verbose = verbose
		self.count = 0                  # Number of mouse pos accounted for.
		self._last_encryptorcount = -1
		self._hash = os.urandom(64)     # Don't look at directly, use get_hash()
		self._shared = mp.Array('c', range(64 + 8 + 8))
		self.active = False             # Process running
		try:
			root = Xlib.display.Display().screen().root
		except Xlib.error.DisplayConnectionError:
			print("HashMouse could not find display")
			return

		self.proc = mp.Process(target=watcher, args=(self._shared, root),
							   kwargs={'min_dots': min_dots, 'verbose': verbose, **kargs})
		self.proc.daemon = True
		self.proc.start()
		self.active = True

	def quit(self):
		if self.active:
			self.proc.terminate()
			self.active = False

	def check_shared(self):
		'''Check to see if self.shared has consistent new data'''
		#d0, d1, d2 = slicer(self._shared, 8, 64, 8, warning=False, debug=True)
		data = self._shared
		d0 = data[0:8]
		d1 = data[8:72]
		d2 = data[72:80]

		if hash8(d0 + d1) != d2:
			# print('Bad data in array?', d0.hex(), d1.hex(), d2.hex())
			return False
		count = int.from_bytes(d0, 'big')
		if count > self.count:
			self.count = count
			self._hash = d1
			return True
		return False


	def get_hash(self):
		'''Return hash to user'''
		self.check_shared()
		return self._hash


	def getcount(self):
		self.check_shared()
		return self.count


	def mrandom(self, count):
		'''
		Use an AES encryptor seeded with bytes from hash to encrypt random data.
		Use this to seed the random number generator: random.seed()
		'''

		if count % 16 != 0:
			request = (count // 16 + 1) * 16
		else:
			request = count

		self.check_shared()
		if self._last_encryptorcount < self.count:
			if self.verbose:
				print("Updated encryptor", self._hash[:32].hex())
			self._last_encryptorcount = self.count
			self.encryptor = AES.new(self._hash[:32], AES.MODE_OFB, os.urandom(16))
		return self.encryptor.encrypt(os.urandom(request))[:count]

	def randint(self, start, stop=None, bits=256):
		'''
		Get a true random number from low to high (inclusive) using get_random()
		bits = number of bits for source of randomness
		'''
		if stop is None:
			stop = start
			start = 0
		size = stop - start + 1
		num = int.from_bytes(self.mrandom(bits // 8), 'big') % size
		return start + num

	def ensure_min(self, min_dots=64):
		'''
		Ensure a minimum number of samples before continuing
		Theoretically every position should provide at least 5 points of data:
		x, y, clock time, cpu time and window id.
		Assuming 2+ bits of randomness per each
		that gives well over 128 bits of randomness
		after only a dozen mouse positions or so,
		but it's set to 64 for a nice margin.
		'''

		self.check_shared()
		if self.count < min_dots:
			sys.stderr.write('Move the mouse randomly to generate more random data:\n')
		else:
			return

		old = 0
		while self.count < min_dots:
			self.check_shared()
			dots = int((self.count) * (64 / min_dots))
			if dots != old:
				sys.stderr.write('\r' + dots * '.')
				sys.stderr.flush()
			old = dots
			time.sleep(1 / 64)
		print()


if __name__ == "__main__":
	TESTER = HashMouse(verbose=1)
	if not TESTER.active:
		sys.exit(1)
	TESTER.ensure_min(16)
	print('\n\nSamples:', 'Current hash state:'.ljust(32), 'Random data from encryptor:')
	while True:
		HASH = TESTER.get_hash()[:16].hex()
		print(str(TESTER.count).ljust(8), HASH, TESTER.mrandom(16).hex())
		time.sleep(1)