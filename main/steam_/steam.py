#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock

import argparse
import socket
import time
import subprocess
import signal
import select
import sqlite3
import threading
import datetime

from steam_.db import DB
from steam_.memory import Memory

from memory_all import Memory_all

class Steam(object):
    """
    Steam Class, each thread will run this class.
    """

    def __init__(self, bind_address, bind_port, tcp_or_udp_string, my_logger):
        self.bind_address = bind_address
        self.bind_port = bind_port
        self.string_tcp_udp = tcp_or_udp_string
        self.my_logger = my_logger

        if(self.string_tcp_udp == 'TCP'):
            #TCP
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((self.bind_address, self.bind_port))
            self.sock.settimeout(5.0)
            self.sock.listen(10)

        elif(self.string_tcp_udp == 'UDP'):
            #udp
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.bind_address, self.bind_port))

        else:
            print('[steam] ERROR in Steam Class')
            self.my_logger.warning('[steam __init__ wrong type input]')

    #add element in memory
    def AddIpMemory(self, ip , count, tempoInicio, tempoFinal, payload):
            Memory.dicio[ip] = (count, tempoInicio, tempoFinal, payload)

    #search element in memory
    def SearchMemory(self,ip):
        if ip in Memory.dicio:
            if(Memory.flag_print == True):
                print(ip, Memory.dicio[ip])
            return False

    #update value in memory(remove ....)
    def UpdateMemory(self,ip):
        if ip in Memory.dicio:
            try:
                #temp value
                ip = ip
                count = Memory.dicio[ip][0]
                tempoInicio = Memory.dicio[ip][1]
                tempoFinal = datetime.datetime.now()
                payload = str(Memory.dicio[ip][3])

                #remove key for update count value
                del Memory.dicio[ip]

                #add count
                count += 1

                #ADD key again
                self.AddIpMemory(ip, count, tempoInicio, tempoFinal, payload)

            except IndexError:
                print("[steam] This index does not exist!")
                self.my_logger.critical('[steam UpdateMemory function IndexError]')
            except KeyError:
                print("[steam] This key is not in the dictionary!")
                self.my_logger.critical('[steam UpdateMemory function KeyError]')
            except TypeError:
                print("[steam] Object does not support (tuple problem)")
                self.my_logger.critical('[steam UpdateMemory function TypeError]')
            except Exception as e:
                print('[steam UpdateMemory function]',e)
                self.my_logger.critical('[steam UpdateMemory function]' + str(e))

    def _i_must_answer(self,ip):
        if(Memory.dicio[ip][0]>Memory.count_max):
            return False
        else:
            return True

    def _port_listening_udp(self):
        if(Memory_all.main_all_prints == True):
            print("[*Loop] [Steam] [UDP], address %s and port %d" % (self.bind_address, self.bind_port))

        while True:
            try:
                data, addr = self.sock.recvfrom(8192) # buffer size is 1024 bytes

                #signal flag stop
                if(Memory_all.dict_lock == True):
                    time.sleep(Memory_all.time_signal_sleep)

                tuple_addr = (addr[0] , self.bind_port,'UDP')
                print('[steam] [UDP] [ip/port/port.]',tuple_addr)
                if ((self.SearchMemory(tuple_addr)) == None ):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] Not ip ')
                    self.AddIpMemory(tuple_addr, 1, datetime.datetime.now(), datetime.datetime.now(), str(data))
                else:
                    if(Memory.flag_print == True):
                        print ('[*MEMORY] True')
                    self.UpdateMemory(tuple_addr)
                #count to use in _control_clean_dict
                Memory._count_use+=1

                if(Memory._count_use > 1000000000):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] _count_use = 1')
                    self.my_logger.warning('[steam _port_listening_udp _count_use]' + str(Memory._count_use))
                    Memory._count_use = 1
                    print(Memory._count_use)

            except KeyboardInterrupt:
                self.sock.close()# Close socket
                self.my_logger.error('[steam UDP KeyboardInterrupt]')
                break

            except Exception as e:
                print('[steam _port_listening_udp function]',e)
                self.my_logger.critical('[steam _port_listening_udp function]' + str(e) + ' DATA: ' + str(data) + ' ADDRESS: ' + str(addr))

            finally:
                if(Memory.TCP_print == True):
                    print('[steam] [UDP] close socket %s:%d'% (self.bind_address, self.bind_port))

    def _port_listening_tcp(self):
        if(Memory_all.main_all_prints == True):
            print("[*Loop] [Steam] [TCP], address %s and port %d" % (self.bind_address, self.bind_port))

        while True:
            try:
                conn, addr = self.sock.accept()

                #signal flag stop
                if(Memory_all.dict_lock == True):
                    time.sleep(Memory_all.time_signal_sleep)

                tuple_addr = (addr[0] , self.bind_port, 'TCP')
                print('[steam] [TCP] [ip/port/prot.]',tuple_addr)
                if ((self.SearchMemory(tuple_addr)) == None ):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] Not ip ')
                    self.AddIpMemory(tuple_addr, 1, datetime.datetime.now(), datetime.datetime.now(), str(conn))
                else:
                    if(Memory.flag_print == True):
                        print ('[*MEMORY] True')
                    self.UpdateMemory(tuple_addr)
                #count to use in _control_clean_dict
                Memory._count_use+=1

                if(Memory._count_use > 1000000000):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] _count_use = 1')
                    self.my_logger.warning('[steam _port_listening_tcp _count_use]' + str(Memory._count_use))
                    Memory._count_use = 1
                    print(Memory._count_use)

                conn.close()
            except KeyboardInterrupt:
                self.sock.close()
                self.my_logger.error('[steam TCP KeyboardInterrupt]')
                break

            except socket.timeout:
                if(Memory.TCP_print == True):
                    print('[steam] [TCP] socket timeout %s:%d'% (self.bind_address, self.bind_port))
                    self.my_logger.error('[steam TCP socket.timeout]')
                pass

            except Exception as e:
                print('[steam _port_listening_tcp function]',e)
                self.my_logger.critical('[steam _port_listening_tcp function]' + str(e))

            finally:
                #self.sock.close()# Close socket
                if(Memory.TCP_print == True):
                    print("[BAD socket] 10? seconds without msg thread die, and run() start a new one %s:%d"% (self.bind_address, self.bind_port))

    def run(self):
        try:
            time.sleep(0.5)

            if(self.string_tcp_udp == 'TCP'):
                t1 = Thread(target=self._port_listening_tcp)
                t1.start()

            elif(self.string_tcp_udp == 'UDP'):
                t2 = Thread(target=self._port_listening_udp)
                t2.start()

            else:
                #big problem
                print('[steam] ERROR in Steam Class')
                self.my_logger.warning('[steam run function else]')

        except KeyboardInterrupt:
            print('[*RUN] Stop working? Thread problem [steam]')
            self.my_logger.error('[steam Run function KeyboardInterrupt]')

        except NameError:
            print('[steam] Run function NameError')
            self.my_logger.critical('[steam Run function NameError]')

        except Exception as e:
            print('[steam Run function]',e)
            self.my_logger.critical('[steam Run function]' + str(e))

    def _endDNSTor(self):
        #Close DNStor
        print('\n[*END] Service Close ...')
