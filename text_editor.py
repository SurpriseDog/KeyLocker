#!/usr/bin/python3

import sys
import shutil
from readchar import readkey


def text_editor(init='', prompt=''):
	'''
	Allow user to edit a line of text complete with support for line wraps
	and a cursor | you can move back and forth with the arrow keys.
	init    = initial text supplied to edit
	prompt  = Decoration presented before the text (not editable and not returned)
	'''

	term_width = shutil.get_terminal_size()[0]
	ptr = len(init)
	text = list(init)
	prompt = list(prompt)

	c = 0
	while True:
		if ptr and ptr > len(text):
			ptr = len(text)

		copy = prompt + text.copy()
		if ptr < len(text):
			copy.insert(ptr + len(prompt), '|')

		# Line wraps support:
		if len(copy) > term_width:
			cut = len(copy) + 3 - term_width
			if ptr > len(copy) / 2:
				copy = ['<'] * 3 + copy[cut:]
			else:
				copy = copy[:-cut] + ['>'] * 3


		# Display current line
		print('\r' * term_width + ''.join(copy), end=' ' * (term_width - len(copy)))


		# Read new character into c
		if c in (53, 54):
			# Page up/down bug
			c = readkey()
			if c == '~':
				continue
		else:
			c = readkey()

		if len(c) > 1:
			# Control Character
			c = ord(c[-1])
			if c == 68:     # Left
				ptr -= 1
			elif c == 67:   # Right
				ptr += 1
			elif c == 53:   # PgDn
				ptr -= term_width // 2
			elif c == 54:   # PgUp
				ptr += term_width // 2
			elif c == 70:   # End
				ptr = len(text)
			elif c == 72:   # Home
				ptr = 0
			else:
				print("\nUnknown control character:", c)
				print("Press ctrl-c to quit.")
				continue
			if ptr < 0:
				ptr = 0
			if ptr > len(text):
				ptr = len(text)

		else:
			num = ord(c)
			if num in (13, 10):  # Enter
				print()
				return ''.join(text)
			elif num == 127:     # Backspace
				if text:
					text.pop(ptr - 1)
					ptr -= 1
			elif num == 3:       # Ctrl-C
				sys.exit(1)
			else:
				# Insert normal character into text.
				text.insert(ptr, c)
				ptr += 1

if __name__ == "__main__":
	print("Result =", text_editor('Edit this text', prompt="Prompt: "))
