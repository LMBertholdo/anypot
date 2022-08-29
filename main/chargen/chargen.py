#!/usr/bin/env python
# -*- coding: utf-8 -*-

import string
import random

from chargen.memory import Memory

class Chargen(object):
	"""
	Chargen class. Generator of strings
	"""

	def __init__(self, my_logger):

		self.my_logger = my_logger

		self.lines_to_send = 24
		self.element = 72

		self.all_aisc = set(string.printable)
		self.remove = set(string.whitespace)

		self.number_of_elements = (len((self.all_aisc).difference(self.remove)))

		self.set_of_aisc = sorted((self.all_aisc).difference(self.remove))
		if(Memory.flag_print == True):
			print(self.set_of_aisc)

	def each_line(self, start_point):
		try:
			line = ''
			aux = start_point
			for i in range(self.element):
				if(aux >= 94):
					consult_value = aux % self.number_of_elements
				else:
					consult_value = aux
				line = line + self.set_of_aisc[abs(consult_value)]
				aux = aux + 1

			#return a string
			return line

		except Exception as e:
			print('[chargen each_line function]',e)
			self.my_logger.critical('[chargen each_line function]' + str(e))

	def string_generator(self):
		try:
			# consult using set 'a' in self.set_of_aisc
			start_point = random.randint(1,93)
			response_end = ''
			for i in range(self.lines_to_send):
				response_end = response_end + self.each_line(start_point) + '\n'
				start_point = start_point + 1

			return response_end

		except Exception as e:
			print('[chargen string_generator function]',e)
			self.my_logger.critical('[chargen string_generator function]' + str(e))

	def function_send(self, t):
		try:
			if(Memory.flag_print == True):
				print('Function send [chargen]')
				print(t)

			def quote_generator():
				while 1:
					for q in t:
						yield str(q)
				return quote_generator()
			return t.encode('utf16')

		except Exception as e:
			print('[chargen function_send function]',e)
			self.my_logger.critical('[chargen function_send function]' + str(e))

	def generator(self):
		try:
			if(Memory.flag_print == True):
				print('[Character Generator]')
			text = self.string_generator()

			if(Memory.flag_print == True):
				print('Generator [chargen]')
				print(text)

			return text

		except Exception as e:
			print('[chargen generator function]',e)
			self.my_logger.critical('[chargen generator function]' + str(e))
