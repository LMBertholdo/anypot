#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import threading
import sys
import argparse
import time

from memcached_.memory import Memory

class Memcached(object):
    """
    Class for Memcached server?
    """
    def __init__(self, socket_one, socket_two,package_info ,address, my_logger):
        self.s = socket_one
        self.sock_server = socket_two
        self.data = package_info
        self.addr = address
        self.my_logger = my_logger

    def send_server_request(self):
        try:
            self.sock_server.send(self.data) # send request to server

            data_recv = self.sock_server.recvfrom(6500)

            if(Memory.flag_print == True):
                print('Data send by localhost : ',data_recv, 'Address: ', self.addr)

            result = data_recv[0].decode('UTF-8')

            if(Memory.flag_print == True):
                print('String localhost: ', result)

            self.s.sendto(bytes(result.encode('UTF-8')),self.addr)

        except ConnectionRefusedError as a:
            print('[memcachedServer send_server_request (localhost service not working)]', a)
            self.my_logger.critical('[memcachedServer send_server_request (localhost service not working)]' + str(a))

        except KeyboardInterrupt as a:
            print(a)
            self.s.close()
            self.sock_server.close()
            self.my_logger.error('[memcachedServer KeyboardInterrupt]')

        except Exception as e:
            print('[memcachedServer send_server_request function]',e)
            self.my_logger.critical('[memcachedServer send_server_request function]' + str(e))

    def run_worker(self):
        self.send_server_request()
