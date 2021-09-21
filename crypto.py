#!/usr/bin/python3
# Crypto Functions

import os
import gc
import sys
import time

from hashlib import sha512
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime

import argon2
import readchar

from sd.common import error, randint, walk, fmt_time, chunk_up, undent

from bitfun import wipe_bytes
from shared import MOUSE_HASHER, rfs, TERM_WIDTH

AES_MODE = AES.MODE_OFB
# Random independent of plaintext, not but, parallelizable good for short segments of data
PASSLEN = 256 + 1		#Maximum password length + 1

def pad(data):
	"In OFB mode, data is padded to 16 byte blocks, but can be cropped to original size."
	if len(data) % 16:
		return bytes(data + get_random(16 - len(data) % 16))
	else:
		return bytes(data)


def encrypt_data(data, key, vector, crop=True):
	'''Encrypt data and pad on an IV at beginning if not already supplied
	key    = 32 byte key
	vector = 16 byte Initialization vector
	crop   = crop to orginal size (OFB mode only)
	'''
	# Create a new encryptor and return the data
	if crop:
		return AES.new(bytes(key), AES_MODE, IV=bytes(vector)).encrypt(pad(data))[:len(data)]
	else:
		return AES.new(bytes(key), AES_MODE, IV=bytes(vector)).encrypt(pad(data))


def decrypt_data(data, key, vector, crop=0):
	"Decrypt the data, Key is 32 bytes and Vector is 16"
	if crop:
		return AES.new(bytes(key), AES_MODE, IV=bytes(vector)).decrypt(pad(data))[:crop]
	else:
		return AES.new(bytes(key), AES_MODE, IV=bytes(vector)).decrypt(pad(data))



def run_argon(key, salt, rounds, mem, threads, buflen=8192, verbose=2):
	'''Run argon and return a bytearray (a mutable type that isn't copied after every interaction)
	rounds
		Number of iterations to run.
		argon2i has a vulneability at 1-2 rounds, but that's not what's used here.
	key
		Sha512key so it can be updated and destroyed
	salt
		Random bytes to accompany key
	mem
		Given in KiB
	threads
		Number of threads to use
	buflen
		Number of bytes produced.
		(Doesn't affect performance, so a larger number is preffered.)
	Argon2_d
		argon_type 0, the default.
		Better than 2i and not vulnerable to attacks on 1-2 rounds
		However it is more vulnerable to side channel attacks. (like on a webserver)

	'''

	if not hasattr(key, 'digest'):
		if type(key) == str:
			key = sha512(key.encode())
		else:
			key = sha512(key)

	if verbose:
		print("Hashing password...", end=' ', flush=True)
		start = time.perf_counter()

	phash = bytearray(argon2.argon2_hash(key.digest(), salt, t=rounds, m=mem//1024, \
	                  p=threads, buflen=buflen, argon_type=0))

	if verbose >= 2:
		# print(round(time.perf_counter() - start, 1), 'seconds')
		print(fmt_time(time.perf_counter() - start))
	elif verbose >= 1:
		print()

	key.update(os.urandom(4096))            # Wipe the key without using mouse_hasher
	return phash


def show_text(array, prompt='', encoding='utf-8', errors='replace'):
	"Show text and then erase it."
	print('\nData is presented below, press Enter to continue:')
	print(prompt, array.decode(encoding=encoding, errors=errors), sep='', end='', flush=True)
	readchar.readkey()
	print('\r' * TERM_WIDTH + ' ' * TERM_WIDTH)


def enter_password(array, prompt='Enter Password', hide='*', minimum=0):
	'''
	#Enter text into a bytearray.
	#Caveat: Last byte will always be zero so you must pass a byteaarray 1 digit longer than the password recevied.
	array  = bytearray()
	prompt = Prompt: before text
	hide     = replace text on prompt with this character
	minimum= minimum length
	'''

	ptr = 0         # Pointer to the correct place in the bytearray

	short_pass_warning = undent('''
	Warning! Short passwords are exceedingly easy to crack!
	For a much more secure password try stringing together words chosen at random
	4 words (or more) makes a very secure password.

	Example: "CorrectHorseBatteryStaple"

	Get some ideas for your own by running the included utility: sd/ranword.py
	''').strip()

	def print_prompt(fill=False):
		text_len = len(prompt) + 1 + ptr + 1

		if not hide:
			print('\r' * TERM_WIDTH + prompt, array[:ptr].decode(), ' ' * (TERM_WIDTH - text_len),
				  end='', flush=True)
			return

		if fill:
			print('\r' * TERM_WIDTH + ' ' * TERM_WIDTH + '\r' * TERM_WIDTH, end='')
			return

		if text_len <= TERM_WIDTH:
			print('\r' * TERM_WIDTH + prompt, hide * ptr, ' ' * (TERM_WIDTH - text_len),
				  end='', flush=True)

	while True:
		print_prompt()
		try:
			array[ptr] = ord(readchar.readkey())
		except TypeError:
			# Pressing control characters like escape will trigger this error.
			continue
		gc.collect()
		junk = [ord(os.urandom(1)) for x in range(PASSLEN)]
		junk[0] = sum(junk)


		if array[ptr] in (13, 10):  # Enter
			array[ptr] = 0
			print_prompt(fill=True)
			if ptr < minimum:
				print("\n\nPasswords must be", minimum, "characters long.")
				print(short_pass_warning)
				continue
			else:
				return ptr

		elif array[ptr] == 127:     # Backspace
			array[ptr] = 0
			if ptr > 0:
				ptr -= 1
				array[ptr] = 0

		elif array[ptr] == 3:       # Ctrl-C
			array[ptr] = 0
			sys.exit(1)

		else:                       # New char
			if ptr < len(array) - 1:
				ptr += 1
			else:
				print("Array limit reached")


def read_pass(verify=True, salt=b'', minimum=4, insecure=None):
	'''Read a password into a hashlib object. Only using mutuable type objects here because strings
	and other objects are copied at every instance leaving stray passwords all over memory.
	verify = verify password after typing
	minimum = min number of characters user must type
	insecure = allows command line passwords

	'''

	def get_pass(key, prompt='Enter Password:'):
		password = bytearray(PASSLEN)

		if insecure:
			if len(insecure) >= PASSLEN:
				error('Insecure password is too long')
			for x, letter in enumerate(insecure):
				password[x] = ord(letter)
		else:
			enter_password(password, prompt=prompt, minimum=minimum)
		key.update(password)
		wipe_bytes(password)
		del password
		gc.collect()


	if verify and not insecure:
		while True:
			key = sha512(salt)
			confirm = sha512(salt)
			get_pass(key, prompt="Enter Password:")
			get_pass(confirm, prompt="Verify Password:")

			# Avoid looking at digest until keys have been hashed with junk data
			a = key.copy()
			junk = os.urandom(4096)
			a.update(junk)
			confirm.update(junk)
			del junk

			if a.digest() == confirm.digest():
				return key
			else:
				print("Passwords don't match, try again.")
				key.update(os.urandom(4096))
				confirm.update(os.urandom(4096))
				del key
				del confirm
	else:
		key = sha512(salt)
		get_pass(key)
		return key


def get_prime(length, ran_bytes):
	'''
	Return a random prime using a byte source.
	Shamir prime doesn't have to be secret, but I went with one anyway.
	length = length in  bytes
	ran_bytes = a source of random data that will return the same prime everytime'''
	assert len(ran_bytes) >= 128
	enc = AES.new(ran_bytes[0:32], AES.MODE_OFB, IV=bytes(ran_bytes[32:48]))

	root = ran_bytes[64:]

	#Pad root if not long enough
	if len(root) < length:
		assert len(root) >= 16
		mult = (length - 1) // len(root) + 1
		#crop = ((length - 1) // 64 + 1) * 64
		crop = chunk_up(length, 64)
		root = (root * mult)[:crop]
		# print(len(root), mult, crop)

	assert len(root) % 16 == 0
	assert len(root) >= length

	def ran_generator(count):
		"Returns pseudorandom data"
		return enc.encrypt(root)[:count]

	return getPrime(length * 8, ran_generator)

# sample = os.urandom(4096)
# reload(crypto); crypto.get_prime(8, sample[:64 + 128])


def get_random(count):
	"Get random bytes by hashing with mouse (if available)"
	if count <= 0:
		return b''

	if MOUSE_HASHER:
		MOUSE_HASHER.ensure_min(64)
		return MOUSE_HASHER.mrandom(count)
	else:
		return os.urandom(count)


def create_random_file(name, min_size, max_size=0):
	"Create a file of random data at name with size"
	if max_size:
		size = randint(min_size, max_size)
	else:
		size = int(min_size)

	if MOUSE_HASHER:
		# Mouse hasher is just encrypting already random data so a high count is not needed.
		# It also throws in os.urandom into the mix anyway
		MOUSE_HASHER.ensure_min(64)

	print("Creating new", rfs(size), "file with name:", name)
	chunk = 1024 * 1024

	with open(name, 'wb') as f:
		written = 0
		while written < size:
			data = get_random(chunk)
			if written + chunk >= size:
				f.write(data[:size-written])
				break
			else:
				f.write(data)
				written += chunk
		f.flush()
		return size


def hash_files(roots, megs=64, verbose=False):
	'''
	Return Sha512 of a filename/directory.
	Hash files are sorted by sha512 sum so the order does not matter
	megs = how many MiB to read before continuing.
	'''
	chunk = 1024**2
	hashes = []
	for root in roots:
		for name in walk(root):
			if not os.access(name, os.R_OK):
				error("Cannot read:", name)
			if verbose:
				print('Hashing:', name)
			h = sha512()
			size = os.path.getsize(name) // chunk		#Size in MiB
			if megs:
				size = min(size, megs)
			with open(name, 'rb') as f:
				for _meg in range(size):
					h.update(f.read(chunk))
				hashes.append(h.digest())
	return sha512(b''.join(sorted(hashes)))
