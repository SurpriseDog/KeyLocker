#!/usr/bin/python3
# Simulates how often the keys mangle each other in Shamir mode
# Requires numpy: python3 -m pip install numpy
# Run with -h to see help menu.

# Notes:
# Collision chance is the chance that any share is on the same slot as another share.
# https://www.wolframalpha.com/input/?i=birthday+problem+calculator&assumption=%22FSelect%22+-%3E+%7B%7B%22BirthdayProblem%22%7D%7D&assumption=%7B%22F%22,+%22BirthdayProblem%22,+%22n%22%7D+-%3E%224%22&assumption=%7B%22F%22,+%22BirthdayProblem%22,+%22pbds%22%7D+-%3E%225555%22


import time
import numpy as np
from sd.common import easy_parse


def percent(num):
	return '{0:.2f}%'.format(num * 100)


def collision_simulator(key_count, slots, min_slots, file_size=1e6, tests=1e6):
	'''Run a million tests and calculate the odds that a key is lost.
	key_count = number of keys
	slots     = backup slots for each key
	file_size = total collision space
	'''

	key_count = int(key_count)
	file_size = int(file_size)
	slots = int(slots)
	min_slots = int(min_slots)
	tests = int(tests)
	slot_size = 64
	num_slots = file_size // slot_size

	slots_used = key_count * slots
	error_tests = 0
	keys_lost = 0
	last_update = time.perf_counter()

	print()
	print("Keys per test          =", key_count)
	print("Slots per key          =", slots)
	print("Minimum slots required =", min_slots)
	print("Space available        =", round(file_size / 1e6, 3), 'MB')
	print("Slots used per file    =", percent(slots_used / num_slots))

	for test in range(tests):
		if not test % 1000:
			if tests - test < 1000 or time.perf_counter() - last_update >= 2:
				print(percent(test / tests).ljust(8),
					  ("Simulation #" + str(test // 1000) + 'k').ljust(18),
					  'Keys lost:', keys_lost, '=', percent(keys_lost / (test * key_count)),
					  '  Collision chance =', percent(error_tests / test),
					  )

				last_update = time.perf_counter()

		offsets = np.random.randint(num_slots, size=slots_used)
		s = np.sort(offsets)
		collisions = set(s[:-1][s[1:] == s[:-1]])

		if not collisions:
			continue
		else:
			error_tests += 1

		for k in range(key_count):
			still_good = slots
			for s in range(slots):
				if offsets[k * slots + s] in collisions:
					still_good -= 1
			if still_good < min_slots:
				keys_lost += 1

	if keys_lost:
		print(keys_lost, 'keys lost =', percent(keys_lost / tests),
			  'in', round(tests / 1e6, 1), 'million tests')
	else:
		print('No keys lost in', round(tests / 1e6, 1), 'million tests')


def main():
	args = [
		("keys", 'key_count', int, 5),
		"Keys per test",

		("slots", '', int, 7),

		("min", 'min_slots', int, 3),
		"Minimum slots required for a complete key. Set to 1 to simulate basic mode.",

		("size", 'file_size', float, 1),
		"Datafile size in megabytes",

		("tests", '', float, 1),
		"Number of tests in millions",
	]

	args = easy_parse(args)
	args.file_size *= 1e6
	args.tests *= 1e6
	collision_simulator(**vars(args))

if __name__ == "__main__":
	main()
