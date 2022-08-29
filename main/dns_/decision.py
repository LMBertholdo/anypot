#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread
from dnslib import DNSRecord, DNSHeader, QTYPE

from dns_.Memory import Memory

import dnslib
import socket
import random
import socket

class Lookup:
	def __init__(self, data, dns_server, dns_port, my_logger):
		self.unbound_server = dns_server
		self.unbound_port = dns_port
		self.data = data
		self.my_logger = my_logger

	def dns_lookup(self):
		"""
		Passes the data to the specified dns_server and returns the response
		"""
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			sock.settimeout(10)
			sock.sendto(self.data, (self.unbound_server, self.unbound_port))

		except Exception as e:
			print('[dns Lookup] Decision DNS/unbound scoket', e)
			self.my_logger.critical('[dns Lookup] Decision DNS/unbound scoket' + str(e) + ' DATA: ' + str(self.data))

		finally:
			return sock.recvfrom(Memory.buffer_size)[0] # (data, addr)
