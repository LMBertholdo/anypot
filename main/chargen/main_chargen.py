#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock
from datetime import datetime

from chargen.chargen import Chargen
from chargen.db import DB_DNSTor
from chargen.memory import Memory
from chargen.ignore import Ig, Modify_ip, Hour_verify, Creat_dict_ig, Ignore_dict

from memory_all import Memory_all

import argparse
import socket
import sqlite3
import threading
import datetime
import time
import select
import subprocess

import csv
import sys

class Proxy_chargen(object):
    """
    Main class of chargen honeypot
    """

    def __init__(self, bind_address, bind_port, my_logger):
        self.port = bind_port
        self.ip = bind_address

        self.my_logger = my_logger

##memory dict
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
                print("[chargen] This index does not exist!")
                self.my_logger.critical('[chargen UpdateMemory function IndexError]')
            except KeyError:
                print("[chargen] This key is not in the dictionary!")
                self.my_logger.critical('[chargen UpdateMemory function KeyError]')
            except TypeError:
                print("[chargen] Object does not support (tuple problem)")
                self.my_logger.critical('[chargen UpdateMemory function TypeError]')
            except Exception as e:
                print('[chargen UpdateMemory function]',e)
                self.my_logger.critical('[chargen UpdateMemory function]' + str(e))

##chargen function call
    @property
    def send_chargen(self):
        try:
            worker_two = Chargen(self.my_logger)
            t = worker_two.generator()

            if(Memory.flag_print == True):
                print('worker 2')
                print(t)

            def quote_generator():
                while 1:
                    for q in t:
                        yield str(q)
                return quote_generator()
            return t.encode('utf16')

        except Exception as a:
            print('[chargen return msg]', a)
            self.my_logger.critical('[chargen send_chargen function]' + str(a))

    #verifica o linite de respostas
    def _i_must_answer(self,ip):
        if(Memory.dicio[ip][0]>Memory.count_max):
            return False
        elif(Memory.dicio[ip][0]>(Memory.count_max - 1)):
            add_ignore_ip = Modify_ip(ip)
            add_ignore_ip.AddIpMemory()
        else:
            #verify ignore dictionay
            worker = Ig(ip)
            b = worker.run()

            if(b == True):
                return False
            else:
                return True

    def _port_listening(self):
        if(Memory_all.main_all_prints == True):
            print('[*Loop] [Chargen] [UDP], address {} and port {}'.format(self.ip,self.port))

        self.socks = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socks.bind((self.ip,self.port))

        while True:
            try:
                data, addr = self.socks.recvfrom(8192)

                #signal flag stop
                if(Memory_all.dict_lock == True):
                    time.sleep(Memory_all.time_signal_sleep)

                if(Memory.flag_print == True):
                    print (addr)

                not_tuple_addr = addr[0] #just ip (same port ...)
                print('[chargen]',not_tuple_addr)

                if ((self.SearchMemory(not_tuple_addr)) == None ):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] Not ip ')

                    #first add memory
                    self.AddIpMemory(not_tuple_addr, 1, datetime.datetime.now(), datetime.datetime.now(), str(data))

                    #verify ignore dictionay
                    worker = Ig(not_tuple_addr)
                    b = worker.run()

                    if(b == True):
                        print('[chargen] Ignore dict [add]', not_tuple_addr)
                    else:
                        qt = (self.send_chargen)
                        if(Memory.flag_print == True):
                            print(qt)

                        self.socks.sendto(bytes(qt),addr)
                else:
                    if(Memory.flag_print == True):
                        print ('[*MEMORY] True')
                    self.UpdateMemory(not_tuple_addr)

                    if(self._i_must_answer(not_tuple_addr) == True):
                        qt = (self.send_chargen)
                        if(Memory.flag_print == True):
                            print(qt)

                        self.socks.sendto(bytes(qt),addr)

                #count to use in _control_clean_dict
                Memory._count_use+=1

                if(Memory._count_use > 1000000000):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] _count_use = 1')
                    self.my_logger.warning('[chargen _port_listening _count_use]' + str(Memory._count_use))
                    Memory._count_use = 1
                    print(Memory._count_use)

            except KeyboardInterrupt:
                self.socks.close()
                self.my_logger.error('[chargen KeyboardInterrupt]')
                break

            except Exception as e:
                print('[chargen _port_listening function]',e)
                print('[chargen _port_listening', datetime.datetime.now(), data, addr)

                self.my_logger.critical('[chargen _port_listening function]' + str(e) + ' DATA: ' + str(data) + ' ADDRESS: ' + str(addr))

    def _supe_thread(self):
        try:
            #time.sleep(60* (Memory.time_thread_clean_dict))
            time.sleep(1)
            if(Memory.flag_print == True):
                print('[*THREAD] Clean dict')
            #print(Memory.dicio)

            #define DB name
            db_name = 'database/dnstor_statistics_chargen.sqlite'

            _background_dict_ = DB_DNSTor(db_name, self.ip, self.port, self.my_logger)
            _background_dict_._run_db()

        except KeyboardInterrupt:
            print('[*THREAD] _supe_thread Stop [chargen]')
            self.my_logger.error('[*THREAD] _supe_thread Stop [chargen] KeyboardInterrupt')

        except Exception as e:
            print('[chargen _supe_thread function]',e)
            self.my_logger.critical('[chargen _supe_thread function]' + str(e))

    def run(self):
        try:
            if(Memory.flag_print == True):
                print('[*LOADING Chargen]')
            time.sleep(1)
            t2 = Thread(target=self._port_listening)
            t2.start()

        except KeyboardInterrupt:
            print('[*RUN] Stop working? Thread problem [chargen]')
            self.my_logger.error('[chargen Run function KeyboardInterrupt]')

        except Exception as e:
            print('[chargen Run function]',e)
            self.my_logger.critical('[chargen Run function]' + str(e))
