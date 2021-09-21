#!/usr/bin/python3
# Randomly choose words from a list using HashMouse to sample the mouse position and time in another thread
# Usage: ./ranword.py <wordfile>


import os
import sys
import time
import secrets

from importlib.util import find_spec
from shutil import get_terminal_size

def load_words(filename):
	"Read the words into a list"
	words = []
	count = 0
	print("Loading words:", end='')
	with open(filename) as f:
		for word in f:
			word = word.strip()
			if word.startswith('#'):
				continue
			words.append(word)
			count += 1
			if not count % 200000:
				print('.', end='', flush=True)
	print()
	return words


def goodbye():
	print('''
	Try downloading a list of the top 10,000 words here:

	https://github.com/first20hours/google-10000-english

	or choose any file with a long list of words arranged vertically.

	For reference, 4 randomly selected words from a 10,000 long word list
	will provide a password complexity of more than 53 bits, which is better
	than a 10 character alphanumeric password that looks like this:'''.strip(), end=' ')

	alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'
	password = ''.join(secrets.choice(alphabet) for i in range(10))
	print(password)
	sys.exit(1)


class HashMouseNoXlib:
	"Replacement HashMouse using the Secrets Library instead"

	def __init__(self, **kargs):
		self.count = 0

	def ensure_min(self, *args):
		pass

	def randint(self, count):
		return secrets.randbelow(count)



def main():
	'''Main Function'''
	if len(sys.argv) > 1:
		filename = sys.argv[1]
	else:
		filename = '/usr/share/dict/words'

	if os.path.exists(filename):
		words = load_words(filename)
	else:
		print("Could not load filename:", filename)
		goodbye()


	if find_spec("Xlib"):
		mhash = HashMouse(verbose=0)
	else:
		mhash = HashMouseNoXlib()

	mhash.ensure_min(16)
	print("Ready! Mouse movements will continue to be hashed in the background.")
	print("The number in the left column shows the mouse sample count")

	print("\n\nPress ctrl+c to quit. ")
	term_width = get_terminal_size()[0]
	line = str(mhash.count)

	while True:
		choice = words[mhash.randint(len(words))]
		new = line + ' ' + choice
		if len(new) < term_width:
			line = new
		else:
			print(line)
			time.sleep(1)
			line = str(mhash.count)


if __name__ == "__main__":
	if not find_spec("Xlib"):
		print("Can't hash mouse movements because Xlib not installed.")
		print("This will limit randomness to that provided by the secrets module (still very good!)")
		print("To install: sudo apt install python3-xlib\n\n")
	else:
		from hash_mouse import HashMouse

	main()