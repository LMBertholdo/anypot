#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock
from datetime import datetime

from qotd.memory import Memory
from qotd.db import DB_DNSTor
from qotd.ignore import Ig, Modify_ip, Hour_verify, Creat_dict_ig, Ignore_dict

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

class Proxy_qotd(object):
    """
    Main class of qotd honeypot
    """

    def __init__(self, path_qotd, bind_address, bind_port, my_logger):
        self.filepath = path_qotd
        self.port = bind_port
        self.ip = bind_address

        self.number_lines = 96
        self.count_line = 1
        self.my_logger = my_logger

        self.msg = "Have a good day."


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
                print("[qotd] This index does not exist!")
                self.my_logger.critical('[qotd UpdateMemory function IndexError]')
            except KeyError:
                print("[qotd] This key is not in the dictionary!")
                self.my_logger.critical('[qotd UpdateMemory function KeyError]')
            except TypeError:
                print("[qotd] Object does not support (tuple problem)")
                self.my_logger.critical('[qotd UpdateMemory function TypeError]')
            except Exception as e:
                print('[qotd UpdateMemory function]',e)
                self.my_logger.critical('[qotd UpdateMemory function]' + str(e))

##quote
    @property
    def send_quote(self):
        try:
            with open(self.filepath, "r") as fo:
                if(Memory.flag_print == True):
                    print ("Qotd file __ ", fo.name)

                #for index in range(self.day):
                for index in range(self.count_line):
                    line = next(fo)

                t = "\n\n{}\n\n ... {}\n".format(line,self.msg)

                if(Memory.flag_print == True):
                    print(t)

                def quote_generator():
                    while 1:
                        for q in t:
                            yield str(q)
                    return quote_generator()
                return t.encode('utf16')

        except Exception as a:
            print('[qotd send_quote]', a)
            self.my_logger.critical('[qotd send_quote function]' + str(a))

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
            print('[*Loop] [qotd] [UDP], address {} and port {}'.format(self.ip,self.port))

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
                print('[qotd]',not_tuple_addr)

                if ((self.SearchMemory(not_tuple_addr)) == None ):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] Not ip ')
                    self.AddIpMemory(not_tuple_addr, 1, datetime.datetime.now(), datetime.datetime.now(), str(data))

                    #verify ignore dictionay
                    worker = Ig(not_tuple_addr)
                    b = worker.run()

                    if(b == True):
                        print('[qotd] Ignore dict [add]', not_tuple_addr)
                    else:
                        qt = (self.send_quote)
                        if(Memory.flag_print == True):
                            print(qt)

                        self.socks.sendto(bytes(qt),addr)

                else:
                    if(Memory.flag_print == True):
                        print ('[*MEMORY] True')
                    self.UpdateMemory(not_tuple_addr)

                    if(self._i_must_answer(not_tuple_addr) == True):
                        qt = (self.send_quote)
                        if(Memory.flag_print == True):
                            print(qt)

                        self.socks.sendto(bytes(qt),addr)

                #count to use in _control_clean_dict
                Memory._count_use+=1

                if(Memory._count_use > 1000000000):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] _count_use = 1')
                    self.my_logger.warning('[qotd _port_listening _count_use]' + str(Memory._count_use))
                    Memory._count_use = 1
                    print(Memory._count_use)

                self.count_line = self.count_line + 1

                if(self.count_line >= self.number_lines):
                    self.count_line = 1
                    if(Memory.flag_print == True):
                        print("[Clean] count lines qotd")

            except KeyboardInterrupt:
                self.socks.close()
                self.my_logger.error('[qotd KeyboardInterrupt]')
                break

            except Exception as e:
                print('[qotd _port_listening function]',e)
                print('[qotd _port_listening', datetime.datetime.now(), data, addr)

                self.my_logger.critical('[qotd _port_listening function]' + str(e) + ' DATA: ' + str(data) + ' ADDRESS: ' + str(addr))

    def _supe_thread(self):
        try:
            #time.sleep(60* (Memory.time_thread_clean_dict))
            if(Memory.flag_print == True):
                print('[*THREAD] Clean dict')
            #print(Memory.dicio)
            #define DB name

            db_name = 'database/dnstor_statistics_qotd.sqlite'

            _background_dict_ = DB_DNSTor(db_name, self.ip, self.port, self.my_logger)
            _background_dict_._run_db()

        except KeyboardInterrupt:
            print('[*THREAD] _supe_thread Stop [qotd]')
            self.my_logger.error('[*THREAD] _supe_thread Stop [qotd] KeyboardInterrupt')

        except Exception as e:
            print('[qotd _supe_thread function]',e)
            self.my_logger.critical('[qotd _supe_thread function]' + str(e))

    def run(self):
        try:
            if(Memory.flag_print == True):
                print('[*LOADING]')
            t2 = Thread(target=self._port_listening)
            t2.start()

        except KeyboardInterrupt:
            print('[*RUN] Stop working? Thread problem [qotd]')
            self.my_logger.error('[qotd Run function KeyboardInterrupt]')

        except Exception as e:
            print('[qotd Run function]',e)
            self.my_logger.critical('[qotd Run function]' + str(e))
