#!/usr/bin/python3
# Usage: ./shamir.py <secret length>

'''
https://en.wikipedia.org/wiki/Shamir's_Secret_Sharing
Split data into a number of secret shares that are individually worthless,
but can be combined to reconstitute the secret text.
This video explains the concept: https://www.youtube.com/watch?v=f_AyjjBAV8c

Understanding the columns:
<share number> <representation of share in 256^x - 1> <actual hex value>

_divmod(), interpolate(), and make_shares() are modified from the code freely available at:
https://github.com/streety/partial-passwords/blob/master/shamir.py
which is licensed under:
https://creativecommons.org/publicdomain/zero/1.0/
http://www.openwebfoundation.org/legal/the-owf-1-0-agreements/owfa-1-0


'''
import os
import sys
import time
import random
import secrets
import itertools

from math import prod as product, factorial

from shared import BYTEORDER
from crypto import get_prime
from bitfun import log, show_bytes, from_bytes, to_bytes
from sd.common import list_get, fmt_time, sig, rns
from sd.columns import auto_cols


def randint(num):
	return secrets.randbelow(num + 1)


def _divmod(num, den, prime):
	'''compute num / den modulo prime prime
	To explain what this means, the return value will be such that
	the following is true: den * _divmod(num, den, prime) % prime == num
	'''
	x = 0
	last_x = 1
	y = 1
	last_y = 0
	while prime != 0:
		quotient = den // prime
		den, prime = prime, den % prime
		x, last_x = last_x - quotient * x, x
		y, last_y = last_y - quotient * y, y
	return num * last_x


def interpolate(prime, indexes, values):
	"Lagrange interpolater"
	nums = []
	dens = []
	for count in range(len(indexes)):
		others = list(indexes)
		cur = others.pop(count)
		nums.append(product(0 - o for o in others))
		dens.append(product(cur - o for o in others))
	den = product(dens)
	total = 0
	for count in range(len(indexes)):
		total += _divmod(nums[count] * den * values[count] % prime, dens[count], prime)
	return (_divmod(total, den, prime) + prime) % prime


def make_shares(minimum, shares, prime, secret, data_len):
	"Make shares with bytes instead of ints, everything else is the same"
	poly = [int.from_bytes(secret, BYTEORDER)] + [randint(prime) for count in range(minimum - 1)]
	poly.reverse()
	for count in range(shares):
		#Evaluate polynomial at index
		total = 0
		for coeff in poly:
			total *= count + 1
			total += coeff
			total %= prime
		yield total.to_bytes(data_len, BYTEORDER)


def get_combos(share_c, maximum=0, info_rate=2):
	'''
	Go through all of the combinations of indexes
	and show info it takes too long
	info_rate = seconds between status updates
	'''
	rand = random.SystemRandom()

	if not maximum:
		maximum = share_c
	last_update = 0
	start = time.perf_counter()

	for minimum in range(1, maximum+1):
		# Try different combinations and see how many are recoverable:
		sample = list(range(1, share_c + 1))
		rand.shuffle(sample)

		# Expected recovery and total combinations
		# expected = int(factorial(valid_c) / (factorial(minimum) * factorial(valid_c - minimum)))
		total = int(factorial(share_c) / (factorial(minimum) * factorial(share_c - minimum)))

		for num, combo in enumerate(itertools.combinations(sample, minimum)):
			yield sorted(combo)

			num += 1
			if not num % 1000 and info_rate:
				elapsed = time.perf_counter() - start
				if elapsed - last_update > 1:
					last_update = elapsed
					rate = num / elapsed

					print("\nTrying", len(combo), "slot combination:", rns(num), 'of', rns(total),
						  'at', rns(rate), 'combos per second')

					'''
					# Doesn't work because succesful combinations are
					# not distributed evenely through itertools.combinations space
					print('Rate:', rns(rate), 'per second')
					print('Expected recovered', expected)
					print("Expected combos per recovery", rns(total / expected))
					print('ETA for first recovery', fmt_time((total / expected) / rate))
					print()
					'''


def _show(binary):
	return (log(binary), '=', show_bytes(binary).split()[-1])

def _print_shares(shares):
	out = []
	for index, share in enumerate(shares):
		out.append([index + 1, *_show(share)])
	auto_cols(out, space=2)


def _tester(secret_min=4, secret_max=128, check_all=True):
	'''
	Try different number of valid and invalid shamir shares and
	make sure the secret is recoverable everytime
	check_all = check all combos instead of stopping at first recovery
	'''
	rand = random.SystemRandom()

	while True:
		print("\n\n\n")

		# Make sure the prime is greater than the secret
		tries = 0
		start = time.perf_counter()
		while True:
			tries += 1
			# A secret text
			secret = os.urandom(rand.randint(secret_min, secret_max))
			length = ((len(secret) + 1) // 64 + 2) * 64
			prime = get_prime(len(secret)+1, os.urandom(length))

			if from_bytes(secret) < prime:
				break

			if tries >= 100:
				# This is only an issue for short primes (under 16 bytes)
				# that have the same prime length as data length.
				# Adding an extra byte to the prime fixes that.
				# In the main code, the prime length is 64 or 128 bytes
				raise ValueError("Gave up after too many tries")


		# Minimum shares to recover secret:
		minimum = rand.randint(3, 6)

		# Total share count
		share_c = rand.randint(minimum, 18)

		# Valid shares left after corruption
		valid_c = rand.randint(minimum, share_c)

		data_len = len(secret) + 1
		shares = list(make_shares(minimum, share_c, prime, secret, data_len))
		gen_time = time.perf_counter() - start


		print('Min:', minimum, 'Valid:', valid_c, 'Total:', share_c)
		print("Secret =", *_show(secret))
		print("Prime  =", *_show(prime))
		if tries > 1:
			print("Prime tries", tries)


		print("\nShares Generated in", fmt_time(gen_time))
		_print_shares(shares)


		# Randomly destroy some of the shares
		cor = [1]*valid_c+[0]*(len(shares)-valid_c)
		rand.shuffle(cor)
		for index, allow in enumerate(cor):
			if not allow:
				shares[index] = b'\x00' * data_len

		print("\nShares Now:", valid_c, '/', len(shares))
		_print_shares(shares)
		shares = [from_bytes(share) for share in shares]

		# Try different combinations and see how many are recoverable:
		recovered, failed = 0, 0
		for num, combo in enumerate(get_combos(share_c, maximum=minimum)):
			ans = interpolate(prime, combo, [shares[x-1] for x in combo])
			if to_bytes(ans, data_len)[:-1] == secret:
				recovered += 1
				if recovered == 1:
					recovery_combos = num
					elapsed = time.perf_counter() - start
					print("\nRecovery Time:", fmt_time(elapsed))
					if not check_all:
						break
			else:
				failed += 1

		yield str(minimum).ljust(8) + str(valid_c).ljust(8) + str(share_c).ljust(8) +\
		      str(recovery_combos).ljust(12) + sig(gen_time).ljust(11) + ' ' + sig(elapsed)


		if check_all:
			# Expected number of combinations that are recoverable:
			expected = int(factorial(valid_c) / (factorial(minimum) * factorial(valid_c - minimum)))
			print("\nCombinations tried:", rns(num))
			print("Expected recovered:")
			print("Actual recovered:  ", recovered)
			print("Percent:", sig((recovered / (recovered + failed)) * 100)+'%')

			if expected != recovered:
				# Random chance means that for very short secrets you can get false recoveries.
				# That's why the actual code has a 64 bit Checksum
				if recovered > expected and len(secret) < 8:
					print("Fake recoveries:", recovered - expected)
					time.sleep(2)
					continue
				break


if __name__ == "__main__":

	with open('shamir.test.output.txt', 'w') as F:
		F.write("Min:    Valid:  Total:  Combos:     Generate:   Restore:\n")
		for line in _tester(int(list_get(sys.argv, 1, 4)), int(list_get(sys.argv, 1, 128))):
			F.write('\n'+line)
